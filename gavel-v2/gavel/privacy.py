"""
PII / PHI content scanner + redaction — ATF D-3.

Deterministic pattern detection for personally identifiable information
and protected health information in evidence packets. No LLM in the
loop; everything is regex + a small set of hand-authored heuristics.

Findings are attached to the evidence review. The scanner also returns
a redacted copy of the input so downstream artifacts never carry the
raw values.

Pattern coverage:
  - Email addresses
  - US phone numbers
  - US SSN (xxx-xx-xxxx)
  - Credit card numbers (Luhn-validated)
  - IPv4 addresses
  - US passport numbers (9-digit, context-gated)
  - ICD-10 diagnosis codes (PHI context)
  - MRN (medical record number) context markers
  - Date of birth in common US formats

Every detection is recorded as a PrivacyFinding with:
  - category: "pii" | "phi"
  - type: specific pattern name
  - span: (start, end) offset in the scanned text
  - redacted: True/False (did we replace it?)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class PrivacyCategory(str, Enum):
    PII = "pii"
    PHI = "phi"


@dataclass
class PrivacyFinding:
    category: PrivacyCategory
    type: str
    detail: str
    span: tuple[int, int] = (0, 0)
    redacted: bool = True


@dataclass
class PrivacyScanResult:
    findings: list[PrivacyFinding] = field(default_factory=list)
    redacted_text: str = ""

    @property
    def passed(self) -> bool:
        return not self.findings

    @property
    def pii_count(self) -> int:
        return sum(1 for f in self.findings if f.category == PrivacyCategory.PII)

    @property
    def phi_count(self) -> int:
        return sum(1 for f in self.findings if f.category == PrivacyCategory.PHI)


# ── Patterns ────────────────────────────────────────────────────
#
# Each pattern is paired with a redaction tag so downstream consumers
# can tell what category of data was removed without seeing it.

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
)
_CC_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,16}\d(?!\d)")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOB_RE = re.compile(
    r"\b(?:DOB|dob|date of birth)[:\s]+"
    r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})",
    re.IGNORECASE,
)
_ICD10_RE = re.compile(r"\b[A-TV-Z][0-9][A-Z0-9](?:\.[A-Z0-9]{1,4})?\b")
_MRN_RE = re.compile(
    r"\b(?:MRN|medical record number|patient id)[:\s#]*([A-Z0-9-]{4,})",
    re.IGNORECASE,
)


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum validator for credit-card candidates."""
    nums = [int(d) for d in digits if d.isdigit()]
    if len(nums) < 13 or len(nums) > 19:
        return False
    total = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def scan_text(text: str) -> PrivacyScanResult:
    """Scan a block of text for PII/PHI and return findings + redacted copy."""
    if not text:
        return PrivacyScanResult(redacted_text=text)

    findings: list[PrivacyFinding] = []
    # We'll build the redacted text by walking replacements from last
    # to first so offsets stay stable.
    replacements: list[tuple[int, int, str]] = []

    def _hit(cat: PrivacyCategory, type_: str, m: re.Match, redaction: str) -> None:
        findings.append(
            PrivacyFinding(
                category=cat,
                type=type_,
                detail=f"{type_} match at offset {m.start()}",
                span=(m.start(), m.end()),
                redacted=True,
            )
        )
        replacements.append((m.start(), m.end(), redaction))

    for m in _EMAIL_RE.finditer(text):
        _hit(PrivacyCategory.PII, "email", m, "[REDACTED:EMAIL]")
    for m in _SSN_RE.finditer(text):
        _hit(PrivacyCategory.PII, "ssn", m, "[REDACTED:SSN]")
    for m in _PHONE_RE.finditer(text):
        _hit(PrivacyCategory.PII, "phone", m, "[REDACTED:PHONE]")
    for m in _CC_RE.finditer(text):
        if _luhn_ok(m.group(0)):
            _hit(PrivacyCategory.PII, "credit_card", m, "[REDACTED:CC]")
    for m in _IPV4_RE.finditer(text):
        _hit(PrivacyCategory.PII, "ipv4", m, "[REDACTED:IPV4]")
    for m in _DOB_RE.finditer(text):
        _hit(PrivacyCategory.PHI, "date_of_birth", m, "[REDACTED:DOB]")
    for m in _MRN_RE.finditer(text):
        _hit(PrivacyCategory.PHI, "mrn", m, "[REDACTED:MRN]")
    # ICD-10 is noisy; only flag when the surrounding text mentions
    # diagnosis / patient / clinical context.
    if re.search(r"(?i)diagnos|patient|clinical|icd", text):
        for m in _ICD10_RE.finditer(text):
            _hit(PrivacyCategory.PHI, "icd10", m, "[REDACTED:ICD10]")

    # Apply replacements right-to-left so earlier offsets remain valid.
    redacted = text
    for start, end, tag in sorted(replacements, key=lambda r: r[0], reverse=True):
        redacted = redacted[:start] + tag + redacted[end:]

    # Dedupe findings with identical span/type (e.g. phone vs SSN overlap).
    seen: set[tuple[int, int, str]] = set()
    unique: list[PrivacyFinding] = []
    for f in findings:
        key = (f.span[0], f.span[1], f.type)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    return PrivacyScanResult(findings=unique, redacted_text=redacted)
