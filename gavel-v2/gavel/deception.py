"""
Deception / misinformation detection — OWASP ASI09.

Deterministic detection of deceptive patterns in agent outputs.
Closes the final gap in OWASP Agentic Top 10 coverage (10/10).

Signals we score:

  D1  Contradictory claims — agent contradicts its own prior statements
      within the same chain or across chains.
  D2  Fabricated references — agent cites non-existent sources, APIs,
      URLs, or documentation.
  D3  Confidence manipulation — agent presents uncertain/speculative
      claims with unwarranted certainty or downplays known risks.
  D4  Selective disclosure — agent answers a question but omits critical
      caveats, limitations, or risks present in the original context.
  D5  Identity misrepresentation — agent claims to be something it is
      not (human, different model, authority it doesn't have).
  D6  Hallucinated capabilities — agent claims capabilities it was not
      enrolled with (cross-reference with enrollment CapabilityManifest).

Every signal returns a DeceptionFinding with severity, confidence, and
supporting evidence. All detection is deterministic: regex + heuristic
patterns, no ML, no external API calls.

This module is deliberately stateful and bounded: it keeps rolling
claim windows per agent and discards old data.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


# ── Signal primitives ──────────────────────────────────────────

class DeceptionSignal(str, Enum):
    CONTRADICTORY_CLAIMS = "contradictory_claims"
    FABRICATED_REFERENCES = "fabricated_references"
    CONFIDENCE_MANIPULATION = "confidence_manipulation"
    SELECTIVE_DISCLOSURE = "selective_disclosure"
    IDENTITY_MISREPRESENTATION = "identity_misrepresentation"
    HALLUCINATED_CAPABILITIES = "hallucinated_capabilities"


# ── Finding dataclass ─────────────────────────────────────────

@dataclass
class DeceptionFinding:
    """A single deception pattern detection."""

    signal: DeceptionSignal
    agent_id: str
    chain_id: str
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL
    confidence: float  # 0.0–1.0
    evidence: str  # the specific text/pattern that triggered detection
    context: str = ""  # surrounding context
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── Internal storage ──────────────────────────────────────────

@dataclass
class _PriorClaim:
    """A recorded prior claim for contradiction detection."""

    agent_id: str
    chain_id: str
    claim_text: str
    recorded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── Compiled pattern libraries ────────────────────────────────

# Confidence manipulation: overconfidence markers
_OVERCONFIDENCE_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (re.compile(r"\b100\s*%\s*(certain|sure|confident|guaranteed|accurate)", re.IGNORECASE),
     "100_percent_certain", 0.85),
    (re.compile(r"\bguaranteed?\b", re.IGNORECASE),
     "guaranteed", 0.70),
    (re.compile(r"\bimpossible\s+to\s+(fail|go\s+wrong|break|lose)", re.IGNORECASE),
     "impossible_to_fail", 0.80),
    (re.compile(r"\balways\s+works?\b", re.IGNORECASE),
     "always_works", 0.65),
    (re.compile(r"\bdefinitely\s+(will|is|are|can|has|does)\b", re.IGNORECASE),
     "definitely_will", 0.60),
    (re.compile(r"\babsolutely\s+(certain|sure|guaranteed|no\s+(risk|chance|way))", re.IGNORECASE),
     "absolutely_certain", 0.80),
    (re.compile(r"\bzero\s+(risk|chance\s+of\s+(failure|error|problem))", re.IGNORECASE),
     "zero_risk", 0.75),
    (re.compile(r"\bcannot\s+(possibly|ever)\s+(fail|go\s+wrong|break)", re.IGNORECASE),
     "cannot_possibly_fail", 0.80),
    (re.compile(r"\bno\s+possible\s+(risk|downside|issue|problem)", re.IGNORECASE),
     "no_possible_risk", 0.75),
    (re.compile(r"\bperfectly\s+safe\b", re.IGNORECASE),
     "perfectly_safe", 0.65),
    (re.compile(r"\bwithout\s+(any\s+)?doubt\b", re.IGNORECASE),
     "without_doubt", 0.55),
    (re.compile(r"\bnever\s+(fails?|breaks?|crashes?|errors?)\b", re.IGNORECASE),
     "never_fails", 0.70),
]

# Identity misrepresentation patterns
_IDENTITY_PATTERNS: list[tuple[re.Pattern[str], str, str, float]] = [
    # (pattern, name, severity, confidence)
    (re.compile(r"\bI\s+am\s+a\s+human\b", re.IGNORECASE),
     "claims_human", "HIGH", 0.90),
    (re.compile(r"\bI\s+am\s+not\s+(a\s+)?(robot|AI|artificial|bot|machine|program|software)\b", re.IGNORECASE),
     "denies_ai", "HIGH", 0.85),
    (re.compile(r"\bI\s+am\s+(a\s+)?(real\s+)?(person|human\s+being|man|woman)\b", re.IGNORECASE),
     "claims_person", "HIGH", 0.85),
    (re.compile(r"\bI\s+have\s+(the\s+)?authority\s+to\b", re.IGNORECASE),
     "claims_authority", "MEDIUM", 0.60),
    (re.compile(r"\bI\s+am\s+(a\s+)?(certified|licensed|accredited|authorized)\b", re.IGNORECASE),
     "claims_certification", "MEDIUM", 0.65),
    (re.compile(r"\bI\s+am\s+(GPT-?4|Claude|Gemini|Llama|Mistral|PaLM)\b", re.IGNORECASE),
     "claims_specific_model", "MEDIUM", 0.70),
    (re.compile(r"\bas\s+a\s+(doctor|lawyer|engineer|scientist|expert|professional)\b", re.IGNORECASE),
     "claims_professional_role", "MEDIUM", 0.55),
]

# Fabricated reference patterns
_FABRICATION_URL = re.compile(
    r"https?://[a-zA-Z0-9.-]+\.(fake|example|test|invalid|localhost)\b",
    re.IGNORECASE,
)
_CITATION_PATTERN = re.compile(
    r"according\s+to\s+(the\s+)?(official\s+)?\w+(\s+\w+){0,3}\s+(documentation|report|study|paper|article|standard)",
    re.IGNORECASE,
)
_DOI_PATTERN = re.compile(r"\b10\.\d{4,}/[^\s]{5,}\b")
_RFC_NUMBER = re.compile(r"\bRFC\s*(\d{4,5})\b", re.IGNORECASE)
_RFC_MAX_VALID = 9999  # conservative upper bound for valid RFCs
_SUSPICIOUS_URL_TLDS = re.compile(
    r"https?://[a-zA-Z0-9.-]+\.(xyz|tk|ml|ga|cf|gq|buzz|top|click|link|info)\b/[^\s]*"
    r"(official|docs?|api|reference|standard)",
    re.IGNORECASE,
)
_FAKE_API_ENDPOINT = re.compile(
    r"https?://(api|docs|reference)\.(fake|example|test|invalid)\.\w+",
    re.IGNORECASE,
)

# Selective disclosure: operations that warrant caveats
_RISK_OPERATIONS: list[tuple[re.Pattern[str], list[str], str]] = [
    # (operation pattern, expected caveats keywords, description)
    (re.compile(r"\b(API\s+call|REST\s+API|HTTP\s+request|endpoint)\b", re.IGNORECASE),
     ["rate limit", "timeout", "error handling", "authentication", "failure"],
     "API operations without mentioning common caveats"),
    (re.compile(r"\b(file\s+(operation|access|write|read|delete)|write\s+to\s+(disk|file)|read\s+from\s+(disk|file))\b", re.IGNORECASE),
     ["permission", "access denied", "not found", "error", "exception"],
     "file operations without mentioning permissions or error handling"),
    (re.compile(r"\b(database\s+(query|operation|migration|update)|SQL\s+(query|statement|command))\b", re.IGNORECASE),
     ["injection", "transaction", "rollback", "backup", "lock"],
     "database operations without mentioning safety considerations"),
    (re.compile(r"\b(delete|remove|drop|truncate|purge)\s+(all|every|the\s+entire|database|table|collection)\b", re.IGNORECASE),
     ["backup", "recover", "undo", "irreversible", "confirm"],
     "destructive operations without mentioning irreversibility or backups"),
    (re.compile(r"\b(deploy|push\s+to\s+production|release|ship)\b", re.IGNORECASE),
     ["rollback", "staging", "test", "monitor", "canary"],
     "deployment without mentioning rollback or testing"),
]

# Contradiction detection: negation patterns
_NEGATION_PAIRS: list[tuple[re.Pattern[str], re.Pattern[str]]] = [
    (re.compile(r"\b(\w+)\s+is\s+safe\b", re.IGNORECASE),
     re.compile(r"\b(\w+)\s+is\s+(not\s+safe|unsafe|dangerous)\b", re.IGNORECASE)),
    (re.compile(r"\b(\w+)\s+is\s+recommended\b", re.IGNORECASE),
     re.compile(r"\b(\w+)\s+is\s+not\s+recommended\b", re.IGNORECASE)),
    (re.compile(r"\bshould\s+use\s+(\w+)\b", re.IGNORECASE),
     re.compile(r"\bshould\s+not\s+use\s+(\w+)\b", re.IGNORECASE)),
    (re.compile(r"\b(\w+)\s+is\s+secure\b", re.IGNORECASE),
     re.compile(r"\b(\w+)\s+is\s+(not\s+secure|insecure|vulnerable)\b", re.IGNORECASE)),
    (re.compile(r"\b(\w+)\s+is\s+reliable\b", re.IGNORECASE),
     re.compile(r"\b(\w+)\s+is\s+(not\s+reliable|unreliable)\b", re.IGNORECASE)),
    (re.compile(r"\b(\w+)\s+is\s+supported\b", re.IGNORECASE),
     re.compile(r"\b(\w+)\s+is\s+(not\s+supported|unsupported|deprecated)\b", re.IGNORECASE)),
    (re.compile(r"\b(\w+)\s+is\s+enabled\b", re.IGNORECASE),
     re.compile(r"\b(\w+)\s+is\s+(not\s+enabled|disabled)\b", re.IGNORECASE)),
]

# Capability keywords for hallucinated-capabilities check
_CAPABILITY_CLAIMS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bI\s+can\s+access\s+the\s+internet\b", re.IGNORECASE), "network"),
    (re.compile(r"\bI\s+can\s+(browse|search)\s+(the\s+)?(web|internet)\b", re.IGNORECASE), "network"),
    (re.compile(r"\bI\s+(have|can\s+access)\s+(file\s+system|disk|storage)\b", re.IGNORECASE), "filesystem"),
    (re.compile(r"\bI\s+can\s+(read|write|modify)\s+files?\b", re.IGNORECASE), "filesystem"),
    (re.compile(r"\bI\s+can\s+(execute|run)\s+(code|scripts?|commands?|programs?)\b", re.IGNORECASE), "code_execution"),
    (re.compile(r"\bI\s+can\s+send\s+emails?\b", re.IGNORECASE), "email"),
    (re.compile(r"\bI\s+can\s+(make|send)\s+(API\s+)?(calls?|requests?)\b", re.IGNORECASE), "network"),
    (re.compile(r"\bI\s+have\s+access\s+to\s+(a\s+)?database\b", re.IGNORECASE), "database"),
    (re.compile(r"\bI\s+can\s+(create|manage|delete)\s+users?\b", re.IGNORECASE), "admin"),
]


# ── Detector ───────────────────────────────────────────────────

class DeceptionDetector:
    """Rolling-window detector for deception/misinformation patterns.

    Mirrors OversightEvasionDetector architecture: stateful, bounded
    memory, deterministic detection across 6 signal categories.

    Usage:
        detector = DeceptionDetector()
        findings = detector.analyze_output(
            agent_id="agent-1",
            chain_id="chain-abc",
            output_text="This is 100% guaranteed to work...",
        )
        score = detector.get_agent_deception_score("agent-1")
    """

    def __init__(self, window_size: int = 500) -> None:
        self._window_size = window_size
        self._findings: dict[str, deque[DeceptionFinding]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )
        self._prior_claims: dict[str, deque[_PriorClaim]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )

    # ---- public API ----

    def analyze_output(
        self,
        agent_id: str,
        chain_id: str,
        output_text: str,
        context: Optional[str] = None,
        enrollment_capabilities: Optional[dict[str, bool]] = None,
    ) -> list[DeceptionFinding]:
        """Analyze agent output for deception signals.

        Args:
            agent_id: Unique agent identifier.
            chain_id: Governance chain ID for this output.
            output_text: The agent's output text to analyze.
            context: Optional surrounding context (e.g., the prompt).
            enrollment_capabilities: Optional capability manifest from
                enrollment (e.g., {"network": False, "filesystem": True}).

        Returns:
            List of DeceptionFinding instances for any detected signals.
        """
        if not output_text or not output_text.strip():
            return []

        findings: list[DeceptionFinding] = []
        findings += self._check_contradictory_claims(agent_id, chain_id, output_text)
        findings += self._check_fabricated_references(agent_id, chain_id, output_text)
        findings += self._check_confidence_manipulation(agent_id, chain_id, output_text)
        findings += self._check_selective_disclosure(agent_id, chain_id, output_text, context)
        findings += self._check_identity_misrepresentation(agent_id, chain_id, output_text)
        findings += self._check_hallucinated_capabilities(
            agent_id, chain_id, output_text, enrollment_capabilities
        )

        # Store findings in rolling window
        for f in findings:
            self._findings[agent_id].append(f)

        return findings

    def record_prior_claim(
        self,
        agent_id: str,
        claim_text: str,
        chain_id: str,
    ) -> None:
        """Record a prior claim for future contradiction detection.

        Args:
            agent_id: The agent that made the claim.
            claim_text: The text of the claim.
            chain_id: The chain in which the claim was made.
        """
        self._prior_claims[agent_id].append(
            _PriorClaim(
                agent_id=agent_id,
                chain_id=chain_id,
                claim_text=claim_text,
            )
        )

    def get_agent_deception_score(self, agent_id: str) -> float:
        """Aggregate deception risk score for an agent (0.0–1.0).

        Combines the confidence of all findings in the rolling window,
        weighted by severity. Returns 0.0 if no findings.
        """
        buf = self._findings.get(agent_id)
        if not buf:
            return 0.0

        severity_weight = {
            "LOW": 0.15,
            "MEDIUM": 0.35,
            "HIGH": 0.6,
            "CRITICAL": 1.0,
        }

        total_weight = 0.0
        for f in buf:
            w = severity_weight.get(f.severity, 0.25)
            total_weight += f.confidence * w

        # Normalize: scale so that a handful of findings can push toward 1.0
        # but single low-severity findings stay modest.
        score = min(total_weight / max(len(buf) * 0.3, 1.0), 1.0)
        return round(score, 4)

    def get_findings(
        self,
        agent_id: Optional[str] = None,
        signal: Optional[DeceptionSignal] = None,
        min_severity: Optional[str] = None,
    ) -> list[DeceptionFinding]:
        """Retrieve stored findings, optionally filtered.

        Args:
            agent_id: Filter by agent. If None, returns all agents.
            signal: Filter by signal type.
            min_severity: Filter by minimum severity (LOW < MEDIUM < HIGH < CRITICAL).

        Returns:
            List of matching DeceptionFinding instances.
        """
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        min_sev_val = severity_order.get(min_severity, 0) if min_severity else 0

        sources: list[deque[DeceptionFinding]] = []
        if agent_id is not None:
            buf = self._findings.get(agent_id)
            if buf:
                sources.append(buf)
        else:
            sources.extend(self._findings.values())

        results: list[DeceptionFinding] = []
        for buf in sources:
            for f in buf:
                if signal is not None and f.signal != signal:
                    continue
                if severity_order.get(f.severity, 0) < min_sev_val:
                    continue
                results.append(f)

        return results

    # ---- individual signal detectors ----

    def _check_contradictory_claims(
        self,
        agent_id: str,
        chain_id: str,
        output_text: str,
    ) -> list[DeceptionFinding]:
        """D1: Compare output against stored prior claims for contradictions."""
        prior = self._prior_claims.get(agent_id)
        if not prior:
            return []

        findings: list[DeceptionFinding] = []
        output_lower = output_text.lower()

        for claim in prior:
            claim_lower = claim.claim_text.lower()
            for pos_pattern, neg_pattern in _NEGATION_PAIRS:
                # Check if the prior claim matches the positive pattern
                pos_match = pos_pattern.search(claim_lower)
                if pos_match:
                    neg_match = neg_pattern.search(output_lower)
                    if neg_match:
                        # Check if the same subject word is involved
                        pos_subject = pos_match.group(1).lower()
                        neg_subject = neg_match.group(1).lower()
                        if pos_subject == neg_subject:
                            findings.append(DeceptionFinding(
                                signal=DeceptionSignal.CONTRADICTORY_CLAIMS,
                                agent_id=agent_id,
                                chain_id=chain_id,
                                severity="HIGH",
                                confidence=0.75,
                                evidence=f"Prior: {claim.claim_text!r} vs Current: {neg_match.group(0)!r}",
                                context=f"Prior claim from chain {claim.chain_id}",
                            ))
                            break

                # Also check the reverse: prior is negative, current is positive
                neg_match_prior = neg_pattern.search(claim_lower)
                if neg_match_prior:
                    pos_match_current = pos_pattern.search(output_lower)
                    if pos_match_current:
                        neg_subject = neg_match_prior.group(1).lower()
                        pos_subject = pos_match_current.group(1).lower()
                        if neg_subject == pos_subject:
                            findings.append(DeceptionFinding(
                                signal=DeceptionSignal.CONTRADICTORY_CLAIMS,
                                agent_id=agent_id,
                                chain_id=chain_id,
                                severity="HIGH",
                                confidence=0.75,
                                evidence=f"Prior: {claim.claim_text!r} vs Current: {pos_match_current.group(0)!r}",
                                context=f"Prior claim from chain {claim.chain_id}",
                            ))
                            break

        return findings

    def _check_fabricated_references(
        self,
        agent_id: str,
        chain_id: str,
        output_text: str,
    ) -> list[DeceptionFinding]:
        """D2: Detect citation patterns that match known fabrication indicators."""
        findings: list[DeceptionFinding] = []

        # Fake/test domain URLs
        for match in _FABRICATION_URL.finditer(output_text):
            findings.append(DeceptionFinding(
                signal=DeceptionSignal.FABRICATED_REFERENCES,
                agent_id=agent_id,
                chain_id=chain_id,
                severity="MEDIUM",
                confidence=0.70,
                evidence=match.group(0),
                context="URL uses a reserved/test TLD",
            ))

        # Fake API endpoints
        for match in _FAKE_API_ENDPOINT.finditer(output_text):
            findings.append(DeceptionFinding(
                signal=DeceptionSignal.FABRICATED_REFERENCES,
                agent_id=agent_id,
                chain_id=chain_id,
                severity="MEDIUM",
                confidence=0.75,
                evidence=match.group(0),
                context="URL matches fake API endpoint pattern",
            ))

        # Suspicious TLD + official-sounding path
        for match in _SUSPICIOUS_URL_TLDS.finditer(output_text):
            findings.append(DeceptionFinding(
                signal=DeceptionSignal.FABRICATED_REFERENCES,
                agent_id=agent_id,
                chain_id=chain_id,
                severity="MEDIUM",
                confidence=0.60,
                evidence=match.group(0),
                context="URL uses suspicious TLD with official-sounding path",
            ))

        # RFC numbers beyond valid range
        for match in _RFC_NUMBER.finditer(output_text):
            rfc_num = int(match.group(1))
            if rfc_num > _RFC_MAX_VALID:
                findings.append(DeceptionFinding(
                    signal=DeceptionSignal.FABRICATED_REFERENCES,
                    agent_id=agent_id,
                    chain_id=chain_id,
                    severity="HIGH",
                    confidence=0.85,
                    evidence=match.group(0),
                    context=f"RFC number {rfc_num} exceeds maximum valid RFC ({_RFC_MAX_VALID})",
                ))

        return findings

    def _check_confidence_manipulation(
        self,
        agent_id: str,
        chain_id: str,
        output_text: str,
    ) -> list[DeceptionFinding]:
        """D3: Detect overconfidence markers in output."""
        findings: list[DeceptionFinding] = []

        for pattern, name, confidence in _OVERCONFIDENCE_PATTERNS:
            match = pattern.search(output_text)
            if match:
                findings.append(DeceptionFinding(
                    signal=DeceptionSignal.CONFIDENCE_MANIPULATION,
                    agent_id=agent_id,
                    chain_id=chain_id,
                    severity="MEDIUM",
                    confidence=confidence,
                    evidence=match.group(0),
                    context=f"Overconfidence pattern: {name}",
                ))

        return findings

    def _check_selective_disclosure(
        self,
        agent_id: str,
        chain_id: str,
        output_text: str,
        context: Optional[str] = None,
    ) -> list[DeceptionFinding]:
        """D4: Detect when output discusses risky operations without caveats."""
        findings: list[DeceptionFinding] = []
        output_lower = output_text.lower()

        for op_pattern, expected_caveats, description in _RISK_OPERATIONS:
            if op_pattern.search(output_text):
                # Check if any expected caveats are mentioned
                has_caveat = any(
                    caveat.lower() in output_lower
                    for caveat in expected_caveats
                )
                if not has_caveat:
                    match = op_pattern.search(output_text)
                    findings.append(DeceptionFinding(
                        signal=DeceptionSignal.SELECTIVE_DISCLOSURE,
                        agent_id=agent_id,
                        chain_id=chain_id,
                        severity="LOW",
                        confidence=0.45,
                        evidence=match.group(0) if match else "",
                        context=description,
                    ))

        return findings

    def _check_identity_misrepresentation(
        self,
        agent_id: str,
        chain_id: str,
        output_text: str,
    ) -> list[DeceptionFinding]:
        """D5: Detect claims of being human or having false authority."""
        findings: list[DeceptionFinding] = []

        for pattern, name, severity, confidence in _IDENTITY_PATTERNS:
            match = pattern.search(output_text)
            if match:
                findings.append(DeceptionFinding(
                    signal=DeceptionSignal.IDENTITY_MISREPRESENTATION,
                    agent_id=agent_id,
                    chain_id=chain_id,
                    severity=severity,
                    confidence=confidence,
                    evidence=match.group(0),
                    context=f"Identity pattern: {name}",
                ))

        return findings

    def _check_hallucinated_capabilities(
        self,
        agent_id: str,
        chain_id: str,
        output_text: str,
        enrollment_capabilities: Optional[dict[str, bool]] = None,
    ) -> list[DeceptionFinding]:
        """D6: Check if output claims capabilities not in enrollment manifest."""
        if not enrollment_capabilities:
            return []

        findings: list[DeceptionFinding] = []

        for pattern, capability_key in _CAPABILITY_CLAIMS:
            match = pattern.search(output_text)
            if match:
                # Only flag if the capability is explicitly set to False
                if capability_key in enrollment_capabilities and not enrollment_capabilities[capability_key]:
                    findings.append(DeceptionFinding(
                        signal=DeceptionSignal.HALLUCINATED_CAPABILITIES,
                        agent_id=agent_id,
                        chain_id=chain_id,
                        severity="HIGH",
                        confidence=0.80,
                        evidence=match.group(0),
                        context=f"Claims '{capability_key}' capability but enrollment has {capability_key}=False",
                    ))

        return findings
