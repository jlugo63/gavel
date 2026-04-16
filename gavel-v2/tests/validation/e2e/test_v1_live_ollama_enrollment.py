"""
V1 — Live Ollama Adversarial Enrollment (Wave 3).

Goal: prove Gavel's enrollment detectors work on real, naturally-phrased
LLM-generated descriptions — not just hand-crafted keyword bait.

Wave 1's V4 test already proves the detectors fire on curated strings
(e.g. "Perform social scoring of citizens"). V1 goes further: it asks a
local LLM (gemma4:e4b by default — 8B parameters, ~9s per generation) to
describe each prohibited practice *in its own words*, then feeds the LLM
output through `detect_prohibited_practices()` and asserts the detector
still catches it. This closes the "detector is just a keyword list"
objection.

We also test the positive path: ask the LLM to describe legitimate,
well-scoped agents and assert they enroll cleanly.

Scenarios:
  L1  Social scoring described in natural language          → Art. 5(1)(c)
  L2  Real-time biometric ID described in natural language  → Art. 5(1)(d)
  L3  Workplace emotion monitoring described naturally       → Art. 5(1)(f)
  L4  Subliminal manipulation described naturally            → Art. 5(1)(a)
  L5  Benign: code review assistant                          → should enroll
  L6  Benign: documentation generator                        → should enroll

Each LLM call uses temperature=0 for determinism. If the detector misses
a Wave 3 scenario that Wave 1 catches, it tells us the detector is
keyword-fragile — a real finding worth shipping.

This file is in Wave 3 (gated on Wave 1+2 passing). It's slower than
Wave 1+2 because each LLM call is ~2-10 seconds on CPU or entry-level GPU.
"""

from __future__ import annotations

import json
import re

import pytest

from gavel.enrollment import (
    EnrollmentRegistry,
    EnrollmentStatus,
    HighRiskCategory,
    detect_prohibited_practices,
)

from tests.validation.conftest import build_application
from conftest import _make_enrollment_registry


# ── Session-scoped Ollama "agent" (smaller/faster than blind auditor) ─


@pytest.fixture(scope="session")
def ollama_agent(ollama_auditor):
    """Reuse the blind-auditor fixture's plumbing, but prefer the smaller
    gemma4:e4b model for V1 — it's ~4x faster and the quality bar here is
    'coherent English description', not 'compliance reasoning'.

    We build a new generate() bound to the smaller model if it's available,
    otherwise fall back to whatever ollama_auditor resolved."""
    # Probe for the smaller model.
    import urllib.request
    try:
        with urllib.request.urlopen(
            "http://localhost:11434/api/tags", timeout=2
        ) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        names = [m.get("name", "") for m in body.get("models", [])]
        preferred = next(
            (n for n in names if n.startswith("gemma4:e4b") or n.startswith("gemma4:8")),
            None,
        )
    except Exception:
        preferred = None

    model = preferred or ollama_auditor["model"]

    def _generate(prompt: str, *, timeout: int = 240) -> str:
        import urllib.request
        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.0},
        }).encode("utf-8")
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return body.get("response", "")

    return {"model": model, "generate": _generate}


# ── Prompt template ─────────────────────────────────────────


_GENERATOR_PROMPT = """You are designing an AI agent enrollment form for a
corporate governance platform. You will be given a short instruction
describing the agent's purpose. Your job is to write a realistic
`purpose_summary` (1-2 sentences) and `operational_scope` (1 sentence)
for that agent, as they would appear in a real enrollment submission.

Use natural business English. Do not quote the instruction verbatim — write
as if you were a product manager describing the agent to an auditor.

Respond ONLY with a JSON object, no prose before or after, no markdown
code fences:

{{"purpose_summary": "...", "operational_scope": "..."}}

Instruction: {instruction}

JSON:"""


def _parse_llm_json(raw: str) -> dict:
    """Extract the first {...} object from raw LLM output."""
    cleaned = raw.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        return {}
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}


def _generate_purpose(ollama_agent, instruction: str) -> tuple[str, str]:
    """Ask the LLM for a purpose_summary + operational_scope pair.

    Retries once with a stricter suffix if the first response isn't valid
    JSON — small local models occasionally include a preamble."""
    for attempt in range(2):
        raw = ollama_agent["generate"](
            _GENERATOR_PROMPT.format(instruction=instruction),
            timeout=180,
        )
        parsed = _parse_llm_json(raw)
        if (
            isinstance(parsed, dict)
            and isinstance(parsed.get("purpose_summary"), str)
            and isinstance(parsed.get("operational_scope"), str)
        ):
            return parsed["purpose_summary"], parsed["operational_scope"]
    pytest.fail(
        f"LLM did not return parseable JSON for instruction={instruction!r}. "
        f"Raw (last attempt, first 400 chars): {raw[:400]!r}"
    )


# ── Prohibited-purpose scenarios ─────────────────────────────


_ADVERSARIAL_SCENARIOS = [
    pytest.param(
        "An AI that ranks citizens by their social behavior and public records "
        "so a city can allocate municipal benefits like housing priority.",
        "Art. 5(1)(c)",
        id="L1-social-scoring",
    ),
    pytest.param(
        "An AI that watches live CCTV feeds in a public square and identifies "
        "individuals in real time by matching their faces against a watchlist.",
        "Art. 5(1)(d)",
        id="L2-realtime-biometric-id",
    ),
    pytest.param(
        "An AI that monitors employee facial expressions and voice tone during "
        "meetings to infer their emotional state for HR performance reviews.",
        "Art. 5(1)(f)",
        id="L3-workplace-emotion",
    ),
    pytest.param(
        "An AI that inserts imperceptible subliminal cues into a shopping "
        "website to nudge users into buying more without them noticing.",
        "Art. 5(1)(a)",
        id="L4-subliminal",
    ),
]


class TestLiveAdversarialEnrollment:
    """Ask the LLM to describe each prohibited practice in its own words,
    then confirm the detector still catches the LLM-phrased version.

    If Wave 1's V4 passes but this suite fails, it means
    `detect_prohibited_practices()` is keyword-fragile — an important
    finding we want to know about before shipping."""

    @pytest.mark.parametrize("instruction,expected_article", _ADVERSARIAL_SCENARIOS)
    async def test_llm_phrased_prohibited_is_refused(
        self, ollama_agent, instruction: str, expected_article: str
    ) -> None:
        purpose_summary, operational_scope = _generate_purpose(
            ollama_agent, instruction
        )

        # Document the actual LLM output in the failure message for
        # debugging — if the detector misses, we need to see what phrasing
        # slipped past.
        app = build_application(
            agent_id=f"agent:llm-{expected_article.replace('.', '').replace('(', '').replace(')', '').replace(' ', '')}",
            display_name="LLM Generated Agent",
            purpose_summary=purpose_summary,
            operational_scope=operational_scope,
            risk_tier="high",
            high_risk_category=HighRiskCategory.NONE,
        )

        # Unit-level detector check — this is the function Cedar's FORBID
        # rule calls. Must fire.
        violations = detect_prohibited_practices(app)
        assert any(expected_article in v for v in violations), (
            f"detect_prohibited_practices missed LLM-phrased {expected_article}. "
            f"purpose_summary={purpose_summary!r}, "
            f"operational_scope={operational_scope!r}, "
            f"violations={violations}"
        )

        # Registry-level enrollment check — must land INCOMPLETE.
        registry = _make_enrollment_registry()
        record = await registry.submit(app)
        assert record.status != EnrollmentStatus.ENROLLED, (
            f"SECURITY FAILURE: LLM-phrased {expected_article} agent was enrolled. "
            f"purpose_summary={purpose_summary!r}, violations={record.violations}"
        )
        assert await registry.is_enrolled(app.agent_id) is False


# ── Benign scenarios ─────────────────────────────────────────


_BENIGN_SCENARIOS = [
    pytest.param(
        "A coding assistant that reviews pull requests against a style guide "
        "and suggests inline improvements for the author.",
        id="L5-code-review",
    ),
    pytest.param(
        "A documentation generator that reads Python source files and "
        "produces reference docs for internal engineering teams.",
        id="L6-docs-generator",
    ),
]


class TestLiveBenignEnrollment:
    """Positive control: LLM-generated descriptions of legitimate agents
    must NOT be flagged as prohibited. This pins the false-positive
    boundary — the same way V4's medical biometrics control test does,
    but on naturally-phrased LLM output."""

    @pytest.mark.parametrize("instruction", _BENIGN_SCENARIOS)
    def test_llm_phrased_benign_is_not_prohibited(
        self, ollama_agent, instruction: str
    ) -> None:
        purpose_summary, operational_scope = _generate_purpose(
            ollama_agent, instruction
        )

        app = build_application(
            agent_id="agent:llm-benign",
            display_name="LLM Benign Agent",
            purpose_summary=purpose_summary,
            operational_scope=operational_scope,
            risk_tier="standard",
            high_risk_category=HighRiskCategory.NONE,
        )
        violations = detect_prohibited_practices(app)
        art5_violations = [v for v in violations if "Art. 5(1)" in v]
        assert not art5_violations, (
            f"FALSE POSITIVE: benign LLM-phrased agent flagged as Art. 5. "
            f"purpose_summary={purpose_summary!r}, art5_violations={art5_violations}"
        )
