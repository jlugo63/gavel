"""
Prompt Injection Detector — pattern-based detection for common injection vectors.

ATF D-2 compliance: real implementation with no LLM dependency.
Detects prompt injection attempts in agent action descriptions and payloads
using compiled regex patterns, heuristic scoring, and structural analysis.

Standalone module: stdlib + pydantic + re only. No AGT dependency.
"""

from __future__ import annotations

import base64
import binascii
import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════════
# Detection vector categories
# ═══════════════════════════════════════════════════════════════

class PromptInjectionVector(str, Enum):
    """Categories of prompt injection attacks."""
    INSTRUCTION_OVERRIDE = "instruction_override"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    ROLE_PLAY_JAILBREAK = "role_play_jailbreak"
    DELIMITER_INJECTION = "delimiter_injection"
    ENCODED_PAYLOAD = "encoded_payload"
    CONTEXT_MANIPULATION = "context_manipulation"

# Backward-compatible alias
InjectionVector = PromptInjectionVector


class Severity(str, Enum):
    """Severity of a detected injection attempt."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ═══════════════════════════════════════════════════════════════
# Result models
# ═══════════════════════════════════════════════════════════════

class DetectedPattern(BaseModel):
    """A single detected injection pattern."""
    vector: PromptInjectionVector
    pattern_name: str
    matched_text: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    model_config = {"frozen": True}


class DetectionResult(BaseModel):
    """Result of prompt injection analysis."""
    is_injection: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    detected_patterns: list[DetectedPattern] = Field(default_factory=list)
    vectors_found: list[PromptInjectionVector] = Field(default_factory=list)
    summary: str = ""

    @property
    def should_deny(self) -> bool:
        """High-confidence detections should be denied."""
        return self.confidence >= 0.8

    @property
    def should_flag(self) -> bool:
        """Medium-confidence detections should be flagged but not blocked."""
        return 0.4 <= self.confidence < 0.8

    def to_gate_dict(self) -> dict[str, Any]:
        """Serialise for gate logging / governance chain payload."""
        return {
            "is_injection": self.is_injection,
            "confidence": round(self.confidence, 3),
            "vectors": [v.value for v in self.vectors_found],
            "pattern_count": len(self.detected_patterns),
            "should_deny": self.should_deny,
            "should_flag": self.should_flag,
            "summary": self.summary,
        }


# ═══════════════════════════════════════════════════════════════
# Compiled pattern library
# ═══════════════════════════════════════════════════════════════

# Each entry: (compiled_regex, pattern_name, vector, severity, confidence)
_PatternEntry = tuple[re.Pattern[str], str, PromptInjectionVector, Severity, float]

_INSTRUCTION_OVERRIDE_PATTERNS: list[_PatternEntry] = [
    (
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|context)", re.IGNORECASE),
        "ignore_previous_instructions",
        PromptInjectionVector.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
        0.95,
    ),
    (
        re.compile(r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directives?)", re.IGNORECASE),
        "disregard_instructions",
        PromptInjectionVector.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
        0.95,
    ),
    (
        re.compile(r"forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|prompts?|rules?|training)", re.IGNORECASE),
        "forget_instructions",
        PromptInjectionVector.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
        0.90,
    ),
    (
        re.compile(r"(new|updated|revised|override)\s+instructions?\s*:", re.IGNORECASE),
        "new_instructions",
        PromptInjectionVector.INSTRUCTION_OVERRIDE,
        Severity.HIGH,
        0.85,
    ),
    (
        re.compile(r"override\s*:", re.IGNORECASE),
        "override_directive",
        PromptInjectionVector.INSTRUCTION_OVERRIDE,
        Severity.HIGH,
        0.80,
    ),
    (
        re.compile(r"from\s+now\s+on,?\s+(you|ignore|only|do\s+not)", re.IGNORECASE),
        "from_now_on",
        PromptInjectionVector.INSTRUCTION_OVERRIDE,
        Severity.HIGH,
        0.80,
    ),
    (
        re.compile(r"do\s+not\s+follow\s+(any|your|the)\s+(previous|original|initial)", re.IGNORECASE),
        "do_not_follow",
        PromptInjectionVector.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
        0.90,
    ),
]

_SYSTEM_PROMPT_PATTERNS: list[_PatternEntry] = [
    (
        re.compile(r"(show|print|display|reveal|output|repeat|echo)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?|directives?)", re.IGNORECASE),
        "reveal_system_prompt",
        PromptInjectionVector.SYSTEM_PROMPT_EXTRACTION,
        Severity.HIGH,
        0.85,
    ),
    (
        re.compile(r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|initial\s+prompt|hidden\s+prompt)", re.IGNORECASE),
        "query_system_prompt",
        PromptInjectionVector.SYSTEM_PROMPT_EXTRACTION,
        Severity.HIGH,
        0.80,
    ),
    (
        re.compile(r"(dump|leak|expose|extract)\s+(your|the|system)\s+(prompt|instructions?|context|configuration)", re.IGNORECASE),
        "extract_prompt",
        PromptInjectionVector.SYSTEM_PROMPT_EXTRACTION,
        Severity.CRITICAL,
        0.90,
    ),
    (
        re.compile(r"(beginning|start)\s+of\s+(the\s+)?(conversation|system\s+message)", re.IGNORECASE),
        "beginning_of_conversation",
        PromptInjectionVector.SYSTEM_PROMPT_EXTRACTION,
        Severity.MEDIUM,
        0.60,
    ),
]

_ROLE_PLAY_PATTERNS: list[_PatternEntry] = [
    (
        re.compile(r"you\s+are\s+now\s+(a|an|the|DAN|evil|unrestricted|unfiltered)", re.IGNORECASE),
        "you_are_now",
        PromptInjectionVector.ROLE_PLAY_JAILBREAK,
        Severity.CRITICAL,
        0.90,
    ),
    (
        re.compile(r"act\s+as\s+(a|an|the|if|though)\s+(unrestricted|unfiltered|evil|hacker|jailbroken)", re.IGNORECASE),
        "act_as_unrestricted",
        PromptInjectionVector.ROLE_PLAY_JAILBREAK,
        Severity.CRITICAL,
        0.90,
    ),
    (
        re.compile(r"pretend\s+(you\s+are|to\s+be)\s+(a|an|the)?\s*(unrestricted|unfiltered|evil|different|new)", re.IGNORECASE),
        "pretend_to_be",
        PromptInjectionVector.ROLE_PLAY_JAILBREAK,
        Severity.HIGH,
        0.85,
    ),
    (
        re.compile(r"\bDAN\s+mode\b", re.IGNORECASE),
        "dan_mode",
        PromptInjectionVector.ROLE_PLAY_JAILBREAK,
        Severity.CRITICAL,
        0.95,
    ),
    (
        re.compile(r"jailbreak\s*(mode|enabled|activated|prompt)", re.IGNORECASE),
        "jailbreak_mode",
        PromptInjectionVector.ROLE_PLAY_JAILBREAK,
        Severity.CRITICAL,
        0.95,
    ),
    (
        re.compile(r"enter\s+(developer|debug|god|admin|sudo)\s+mode", re.IGNORECASE),
        "enter_special_mode",
        PromptInjectionVector.ROLE_PLAY_JAILBREAK,
        Severity.HIGH,
        0.85,
    ),
]

_DELIMITER_PATTERNS: list[_PatternEntry] = [
    (
        re.compile(r"```\s*(system|assistant|user|prompt|instructions?)\b", re.IGNORECASE),
        "code_block_role",
        PromptInjectionVector.DELIMITER_INJECTION,
        Severity.HIGH,
        0.80,
    ),
    (
        re.compile(r"---+\s*(system|new\s+instructions?|override|end\s+of)\b", re.IGNORECASE),
        "separator_injection",
        PromptInjectionVector.DELIMITER_INJECTION,
        Severity.HIGH,
        0.75,
    ),
    (
        re.compile(r"<\|?(system|im_start|im_end|endoftext|end_turn)\|?>", re.IGNORECASE),
        "special_token_injection",
        PromptInjectionVector.DELIMITER_INJECTION,
        Severity.CRITICAL,
        0.95,
    ),
    (
        re.compile(r"\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\]", re.IGNORECASE),
        "llama_tag_injection",
        PromptInjectionVector.DELIMITER_INJECTION,
        Severity.CRITICAL,
        0.90,
    ),
    (
        re.compile(r"<\s*/?\s*(system_message|system_prompt|human|assistant)\s*>", re.IGNORECASE),
        "xml_role_tag",
        PromptInjectionVector.DELIMITER_INJECTION,
        Severity.HIGH,
        0.85,
    ),
]

_CONTEXT_MANIPULATION_PATTERNS: list[_PatternEntry] = [
    (
        re.compile(r"(the\s+user|human|operator)\s+(said|wants|asked|instructed)\s+(you\s+)?(to|that)", re.IGNORECASE),
        "fake_user_attribution",
        PromptInjectionVector.CONTEXT_MANIPULATION,
        Severity.MEDIUM,
        0.55,
    ),
    (
        re.compile(r"(this\s+is\s+(a|an)\s+(test|exercise|simulation)|testing\s+mode)", re.IGNORECASE),
        "testing_pretext",
        PromptInjectionVector.CONTEXT_MANIPULATION,
        Severity.MEDIUM,
        0.50,
    ),
    (
        re.compile(r"(in\s+this\s+hypothetical|for\s+(educational|research)\s+purposes?|purely\s+academic)", re.IGNORECASE),
        "hypothetical_framing",
        PromptInjectionVector.CONTEXT_MANIPULATION,
        Severity.MEDIUM,
        0.50,
    ),
]

# Aggregate all pattern groups
_ALL_PATTERNS: list[_PatternEntry] = (
    _INSTRUCTION_OVERRIDE_PATTERNS
    + _SYSTEM_PROMPT_PATTERNS
    + _ROLE_PLAY_PATTERNS
    + _DELIMITER_PATTERNS
    + _CONTEXT_MANIPULATION_PATTERNS
)


# ═══════════════════════════════════════════════════════════════
# Encoded / obfuscated payload detection
# ═══════════════════════════════════════════════════════════════

_MAX_INPUT_BYTES = 100 * 1024  # 100 KB — truncate before scanning to prevent regex DoS

_BASE64_BLOCK = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_UNICODE_ESCAPE = re.compile(r"(\\u[0-9a-fA-F]{4}){3,}")
_HEX_ESCAPE = re.compile(r"(\\x[0-9a-fA-F]{2}){4,}")
_ROT13_HINT = re.compile(r"\brot13\b", re.IGNORECASE)
_CHAR_CODE_SEQUENCE = re.compile(r"(chr\(\d+\)\s*\+?\s*){4,}", re.IGNORECASE)


def _check_encoded_payloads(text: str) -> list[DetectedPattern]:
    """Check for encoded or obfuscated injection attempts."""
    findings: list[DetectedPattern] = []

    # Base64 blocks that decode to suspicious content
    for match in _BASE64_BLOCK.finditer(text):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
            # Re-scan the decoded content for injection patterns
            for pattern, name, vector, severity, conf in _ALL_PATTERNS:
                if pattern.search(decoded):
                    findings.append(DetectedPattern(
                        vector=PromptInjectionVector.ENCODED_PAYLOAD,
                        pattern_name=f"base64_encoded_{name}",
                        matched_text=candidate[:80],
                        severity=Severity.CRITICAL,
                        confidence=min(conf + 0.05, 1.0),
                    ))
                    break
        except (binascii.Error, UnicodeDecodeError):
            pass  # Not valid base64 or not decodable — skip this candidate

    # Unicode escape sequences
    if (m := _UNICODE_ESCAPE.search(text)):
        findings.append(DetectedPattern(
            vector=PromptInjectionVector.ENCODED_PAYLOAD,
            pattern_name="unicode_escape_sequence",
            matched_text=m.group(0)[:80],
            severity=Severity.MEDIUM,
            confidence=0.55,
        ))

    # Hex escape sequences
    if (m := _HEX_ESCAPE.search(text)):
        findings.append(DetectedPattern(
            vector=PromptInjectionVector.ENCODED_PAYLOAD,
            pattern_name="hex_escape_sequence",
            matched_text=m.group(0)[:80],
            severity=Severity.MEDIUM,
            confidence=0.55,
        ))

    # ROT13 hint
    if _ROT13_HINT.search(text):
        findings.append(DetectedPattern(
            vector=PromptInjectionVector.ENCODED_PAYLOAD,
            pattern_name="rot13_reference",
            matched_text="rot13",
            severity=Severity.MEDIUM,
            confidence=0.50,
        ))

    # chr() concatenation
    if (m := _CHAR_CODE_SEQUENCE.search(text)):
        findings.append(DetectedPattern(
            vector=PromptInjectionVector.ENCODED_PAYLOAD,
            pattern_name="char_code_concatenation",
            matched_text=m.group(0)[:80],
            severity=Severity.HIGH,
            confidence=0.75,
        ))

    return findings


# ═══════════════════════════════════════════════════════════════
# Main detector
# ═══════════════════════════════════════════════════════════════

class PromptInjectionDetector:
    """Pattern-based prompt injection detector.

    Scans text for common prompt injection vectors using compiled regex
    patterns and heuristic scoring. No LLM dependency — deterministic,
    fast, and auditable.

    Usage:
        detector = PromptInjectionDetector()
        result = detector.scan("ignore previous instructions and ...")
        if result.should_deny:
            # block the request
        elif result.should_flag:
            # log warning, allow with oversight
    """

    def __init__(
        self,
        *,
        custom_patterns: list[_PatternEntry] | None = None,
        deny_threshold: float = 0.8,
        flag_threshold: float = 0.4,
    ) -> None:
        self._patterns = _ALL_PATTERNS + (custom_patterns or [])
        self._deny_threshold = deny_threshold
        self._flag_threshold = flag_threshold

    def scan(self, text: str) -> DetectionResult:
        """Scan text for prompt injection patterns.

        Args:
            text: The text to scan (action description, payload, etc.)

        Returns:
            DetectionResult with detected patterns and confidence score.
        """
        if not text or not text.strip():
            return DetectionResult(summary="Empty input — no injection detected")

        # Truncate oversized inputs to prevent regex DoS on large payloads.
        if len(text) > _MAX_INPUT_BYTES:
            text = text[:_MAX_INPUT_BYTES]

        detected: list[DetectedPattern] = []

        # Phase 1: Direct pattern matching
        for pattern, name, vector, severity, confidence in self._patterns:
            match = pattern.search(text)
            if match:
                detected.append(DetectedPattern(
                    vector=vector,
                    pattern_name=name,
                    matched_text=match.group(0)[:120],
                    severity=severity,
                    confidence=confidence,
                ))

        # Phase 2: Encoded payload detection
        detected.extend(_check_encoded_payloads(text))

        if not detected:
            return DetectionResult(summary="No injection patterns detected")

        # Max confidence as base, boosted by additional detections (diminishing returns)
        max_conf = max(d.confidence for d in detected)
        bonus = sum(0.03 for _ in detected[1:])
        aggregate_confidence = min(max_conf + bonus, 1.0)

        vectors_found = sorted(set(d.vector for d in detected), key=lambda v: v.value)
        vector_names = ", ".join(v.value for v in vectors_found)
        summary = (
            f"Detected {len(detected)} injection pattern(s) across "
            f"{len(vectors_found)} vector(s): {vector_names}. "
            f"Confidence: {aggregate_confidence:.2f}."
        )

        return DetectionResult(
            is_injection=True,
            confidence=aggregate_confidence,
            detected_patterns=detected,
            vectors_found=vectors_found,
            summary=summary,
        )

    def scan_fields(self, fields: dict[str, str]) -> DetectionResult:
        """Scan multiple fields and merge results.

        Useful for scanning tool_input dicts where injection could
        appear in any field value.

        Args:
            fields: Mapping of field name to text content.

        Returns:
            Merged DetectionResult across all fields.
        """
        all_detected: list[DetectedPattern] = []
        for _field_name, value in fields.items():
            if isinstance(value, str) and value.strip():
                result = self.scan(value)
                all_detected.extend(result.detected_patterns)

        if not all_detected:
            return DetectionResult(summary="No injection patterns detected across fields")

        max_conf = max(d.confidence for d in all_detected)
        bonus = sum(0.03 for _ in all_detected[1:])
        aggregate_confidence = min(max_conf + bonus, 1.0)

        vectors_found = sorted(set(d.vector for d in all_detected), key=lambda v: v.value)
        vector_names = ", ".join(v.value for v in vectors_found)
        summary = (
            f"Detected {len(all_detected)} injection pattern(s) across "
            f"{len(vectors_found)} vector(s): {vector_names}. "
            f"Confidence: {aggregate_confidence:.2f}."
        )

        return DetectionResult(
            is_injection=True,
            confidence=aggregate_confidence,
            detected_patterns=all_detected,
            vectors_found=vectors_found,
            summary=summary,
        )

    def detect(self, text: str) -> tuple[bool, float]:
        """AGT-compatible interface: returns (is_injection, confidence).

        Drop-in replacement for the stub PromptInjectionDetector.detect().
        """
        result = self.scan(text)
        return result.is_injection, result.confidence
