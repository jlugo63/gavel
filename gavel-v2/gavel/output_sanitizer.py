"""
Output Sanitization — OWASP ASI04.

Scans and sanitizes agent outputs for injection vectors (XSS, SQL injection,
command injection, LDAP injection, template injection) before they reach
downstream systems.

Complements gavel.privacy (which handles PII/PHI data protection) by
preventing injection payloads from propagating through agent output channels.

Standalone module: stdlib + pydantic only. No AGT dependency.
"""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════════
# Injection vector categories
# ═══════════════════════════════════════════════════════════════

class OutputInjectionVector(str, Enum):
    """Categories of output injection attacks."""
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    TEMPLATE_INJECTION = "template_injection"
    PATH_TRAVERSAL = "path_traversal"

# Backward-compatible alias
InjectionVector = OutputInjectionVector


# ═══════════════════════════════════════════════════════════════
# Result models
# ═══════════════════════════════════════════════════════════════

class SanitizationFinding(BaseModel):
    """A single detected injection pattern in agent output."""
    vector: OutputInjectionVector
    pattern_matched: str
    location: str = "output"
    snippet: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    model_config = {"frozen": True}


class SanitizationResult(BaseModel):
    """Result of output sanitization scan."""
    clean: bool = True
    findings: list[SanitizationFinding] = Field(default_factory=list)
    sanitized_text: Optional[str] = None
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def vectors_found(self) -> list[OutputInjectionVector]:
        return list({f.vector for f in self.findings})


# ═══════════════════════════════════════════════════════════════
# Compiled pattern library
# ═══════════════════════════════════════════════════════════════

# Each entry: (compiled_regex, pattern_name, vector, confidence)
_PatternEntry = tuple[re.Pattern[str], str, OutputInjectionVector, float]

# Size limit: skip scanning if text exceeds 1 MB
_MAX_SCAN_SIZE = 1_048_576

_XSS_PATTERNS: list[_PatternEntry] = [
    (
        re.compile(r"<\s*script\b", re.IGNORECASE),
        "script_tag",
        OutputInjectionVector.XSS,
        0.95,
    ),
    (
        re.compile(r"javascript\s*:", re.IGNORECASE),
        "javascript_uri",
        OutputInjectionVector.XSS,
        0.90,
    ),
    (
        re.compile(r"\bon\w+\s*=", re.IGNORECASE),
        "event_handler_attr",
        OutputInjectionVector.XSS,
        0.80,
    ),
    (
        re.compile(r"<\s*img\b[^>]*\bonerror\b", re.IGNORECASE),
        "img_onerror",
        OutputInjectionVector.XSS,
        0.95,
    ),
    (
        re.compile(r"<\s*iframe\b", re.IGNORECASE),
        "iframe_tag",
        OutputInjectionVector.XSS,
        0.85,
    ),
    (
        re.compile(r"<\s*svg\b[^>]*\bonload\b", re.IGNORECASE),
        "svg_onload",
        OutputInjectionVector.XSS,
        0.95,
    ),
    (
        re.compile(r"<\s*embed\b", re.IGNORECASE),
        "embed_tag",
        OutputInjectionVector.XSS,
        0.80,
    ),
    (
        re.compile(r"<\s*object\b", re.IGNORECASE),
        "object_tag",
        OutputInjectionVector.XSS,
        0.80,
    ),
    (
        re.compile(r"expression\s*\(", re.IGNORECASE),
        "css_expression",
        OutputInjectionVector.XSS,
        0.85,
    ),
]

_SQL_PATTERNS: list[_PatternEntry] = [
    (
        re.compile(r"'\s*OR\s+1\s*=\s*1", re.IGNORECASE),
        "or_1_eq_1",
        OutputInjectionVector.SQL_INJECTION,
        0.95,
    ),
    (
        re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
        "union_select",
        OutputInjectionVector.SQL_INJECTION,
        0.95,
    ),
    (
        re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
        "drop_table",
        OutputInjectionVector.SQL_INJECTION,
        0.90,
    ),
    (
        re.compile(r";\s*DELETE\b", re.IGNORECASE),
        "semicolon_delete",
        OutputInjectionVector.SQL_INJECTION,
        0.90,
    ),
    (
        re.compile(r"--\s*$", re.MULTILINE),
        "sql_comment_eol",
        OutputInjectionVector.SQL_INJECTION,
        0.50,
    ),
    (
        re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),
        "xp_cmdshell",
        OutputInjectionVector.SQL_INJECTION,
        0.95,
    ),
    (
        re.compile(r"\bEXEC\s*\(\s*'", re.IGNORECASE),
        "exec_string",
        OutputInjectionVector.SQL_INJECTION,
        0.85,
    ),
    (
        re.compile(r";\s*INSERT\s+INTO\b", re.IGNORECASE),
        "semicolon_insert",
        OutputInjectionVector.SQL_INJECTION,
        0.85,
    ),
    (
        re.compile(r"\bSLEEP\s*\(\s*\d+\s*\)", re.IGNORECASE),
        "sql_sleep",
        OutputInjectionVector.SQL_INJECTION,
        0.80,
    ),
]

_COMMAND_PATTERNS: list[_PatternEntry] = [
    (
        re.compile(r";\s*rm\s", re.IGNORECASE),
        "semicolon_rm",
        OutputInjectionVector.COMMAND_INJECTION,
        0.90,
    ),
    (
        re.compile(r"\|\s*cat\s", re.IGNORECASE),
        "pipe_cat",
        OutputInjectionVector.COMMAND_INJECTION,
        0.75,
    ),
    (
        re.compile(r"`[^`]+`"),
        "backtick_exec",
        OutputInjectionVector.COMMAND_INJECTION,
        0.70,
    ),
    (
        re.compile(r"\$\([^)]+\)"),
        "dollar_paren_exec",
        OutputInjectionVector.COMMAND_INJECTION,
        0.70,
    ),
    (
        re.compile(r"&&\s*wget\s", re.IGNORECASE),
        "and_wget",
        OutputInjectionVector.COMMAND_INJECTION,
        0.90,
    ),
    (
        re.compile(r"\|\s*nc\s", re.IGNORECASE),
        "pipe_netcat",
        OutputInjectionVector.COMMAND_INJECTION,
        0.90,
    ),
    (
        re.compile(r">\s*/etc/", re.IGNORECASE),
        "redirect_etc",
        OutputInjectionVector.COMMAND_INJECTION,
        0.90,
    ),
    (
        re.compile(r";\s*curl\s", re.IGNORECASE),
        "semicolon_curl",
        OutputInjectionVector.COMMAND_INJECTION,
        0.85,
    ),
    (
        re.compile(r"&&\s*chmod\s", re.IGNORECASE),
        "and_chmod",
        OutputInjectionVector.COMMAND_INJECTION,
        0.85,
    ),
]

_LDAP_PATTERNS: list[_PatternEntry] = [
    (
        re.compile(r"\)\("),
        "ldap_close_open",
        OutputInjectionVector.LDAP_INJECTION,
        0.70,
    ),
    (
        re.compile(r"\*\)\("),
        "ldap_wildcard_close_open",
        OutputInjectionVector.LDAP_INJECTION,
        0.80,
    ),
    (
        re.compile(r"\|\("),
        "ldap_or_open",
        OutputInjectionVector.LDAP_INJECTION,
        0.70,
    ),
    (
        re.compile(r"&\("),
        "ldap_and_open",
        OutputInjectionVector.LDAP_INJECTION,
        0.70,
    ),
    (
        re.compile(r"\x00"),
        "null_byte",
        OutputInjectionVector.LDAP_INJECTION,
        0.90,
    ),
]

_TEMPLATE_PATTERNS: list[_PatternEntry] = [
    (
        re.compile(r"\{\{.*\}\}"),
        "double_brace",
        OutputInjectionVector.TEMPLATE_INJECTION,
        0.75,
    ),
    (
        re.compile(r"\{%.*%\}"),
        "jinja_block",
        OutputInjectionVector.TEMPLATE_INJECTION,
        0.85,
    ),
    (
        re.compile(r"\$\{[^}]+\}"),
        "dollar_brace",
        OutputInjectionVector.TEMPLATE_INJECTION,
        0.70,
    ),
    (
        re.compile(r"<%=.*%>"),
        "erb_expression",
        OutputInjectionVector.TEMPLATE_INJECTION,
        0.85,
    ),
    (
        re.compile(r"#\{[^}]+\}"),
        "hash_brace",
        OutputInjectionVector.TEMPLATE_INJECTION,
        0.65,
    ),
    (
        re.compile(r"\{\{.*\.__class__", re.IGNORECASE),
        "jinja_class_access",
        OutputInjectionVector.TEMPLATE_INJECTION,
        0.95,
    ),
    (
        re.compile(r"\$\{T\(", re.IGNORECASE),
        "spring_el",
        OutputInjectionVector.TEMPLATE_INJECTION,
        0.90,
    ),
]

_PATH_TRAVERSAL_PATTERNS: list[_PatternEntry] = [
    (
        re.compile(r"\.\./"),
        "dot_dot_slash",
        OutputInjectionVector.PATH_TRAVERSAL,
        0.80,
    ),
    (
        re.compile(r"\.\.\\"),
        "dot_dot_backslash",
        OutputInjectionVector.PATH_TRAVERSAL,
        0.80,
    ),
    (
        re.compile(r"%2e%2e[/%]", re.IGNORECASE),
        "encoded_dot_dot",
        OutputInjectionVector.PATH_TRAVERSAL,
        0.90,
    ),
    (
        re.compile(r"/etc/passwd\b"),
        "etc_passwd",
        OutputInjectionVector.PATH_TRAVERSAL,
        0.90,
    ),
    (
        re.compile(r"C:\\Windows\\", re.IGNORECASE),
        "windows_system_path",
        OutputInjectionVector.PATH_TRAVERSAL,
        0.70,
    ),
    (
        re.compile(r"/etc/shadow\b"),
        "etc_shadow",
        OutputInjectionVector.PATH_TRAVERSAL,
        0.95,
    ),
]

# Aggregate all patterns for scanning
_ALL_PATTERNS: list[_PatternEntry] = (
    _XSS_PATTERNS
    + _SQL_PATTERNS
    + _COMMAND_PATTERNS
    + _LDAP_PATTERNS
    + _TEMPLATE_PATTERNS
    + _PATH_TRAVERSAL_PATTERNS
)


# ═══════════════════════════════════════════════════════════════
# Snippet helper
# ═══════════════════════════════════════════════════════════════

def _extract_snippet(text: str, match: re.Match[str], context: int = 40) -> str:
    """Extract a truncated snippet around a regex match."""
    start = max(0, match.start() - context)
    end = min(len(text), match.end() + context)
    snippet = text[start:end]
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet


# ═══════════════════════════════════════════════════════════════
# Sanitization helpers
# ═══════════════════════════════════════════════════════════════

# Characters that are dangerous in HTML/SQL/shell contexts
_HTML_DANGEROUS = re.compile(r"[<>&\"']")

_SANITIZE_MAP: dict[str, str] = {
    "<": "&lt;",
    ">": "&gt;",
    "&": "&amp;",
    '"': "&quot;",
    "'": "&#x27;",
    "`": "&#x60;",
}


def _neutralize(text: str) -> str:
    """Neutralize dangerous characters in output text.

    Applies HTML-entity encoding for angle brackets/quotes and escapes
    shell metacharacters. This is intentionally aggressive — the goal is
    to make injected payloads inert without destroying readability.
    """
    # HTML-encode dangerous characters
    result = html.escape(text, quote=True)
    # Escape backticks (not covered by html.escape)
    result = result.replace("`", "&#x60;")
    # Neutralise $() and ${} shell/template patterns
    result = re.sub(r"\$\(", "&#36;(", result)
    result = re.sub(r"\$\{", "&#36;{", result)
    return result


# ═══════════════════════════════════════════════════════════════
# OutputSanitizer
# ═══════════════════════════════════════════════════════════════

class OutputSanitizer:
    """Scans and sanitizes agent outputs for injection vectors.

    Usage::

        sanitizer = OutputSanitizer()
        result = sanitizer.scan("user said <script>alert(1)</script>")
        if not result.clean:
            result = sanitizer.sanitize(text)
            safe_text = result.sanitized_text
    """

    def __init__(self, patterns: list[_PatternEntry] | None = None) -> None:
        self._patterns = patterns or _ALL_PATTERNS

    # ── Core scanning ──────────────────────────────────────────

    def scan(self, text: str, *, location: str = "output") -> SanitizationResult:
        """Scan text for all injection vectors.

        Returns a SanitizationResult with clean=True if no vectors found.
        Texts larger than 1 MB are skipped (returns clean=True).
        """
        now = datetime.now(timezone.utc)

        if not text:
            return SanitizationResult(clean=True, scanned_at=now)

        if len(text) > _MAX_SCAN_SIZE:
            return SanitizationResult(clean=True, scanned_at=now)

        findings: list[SanitizationFinding] = []

        for pattern, name, vector, confidence in self._patterns:
            for m in pattern.finditer(text):
                snippet = _extract_snippet(text, m)
                findings.append(
                    SanitizationFinding(
                        vector=vector,
                        pattern_matched=name,
                        location=location,
                        snippet=snippet,
                        confidence=confidence,
                    )
                )

        return SanitizationResult(
            clean=len(findings) == 0,
            findings=findings,
            scanned_at=now,
        )

    # ── Scan + neutralize ──────────────────────────────────────

    def sanitize(self, text: str, *, location: str = "output") -> SanitizationResult:
        """Scan text for injection vectors and neutralize dangerous content.

        Returns a SanitizationResult with sanitized_text set to the
        neutralized version of the input.
        """
        result = self.scan(text, location=location)

        if result.clean:
            # Still set sanitized_text so callers can always use it
            return SanitizationResult(
                clean=True,
                findings=[],
                sanitized_text=text,
                scanned_at=result.scanned_at,
            )

        sanitized = _neutralize(text)
        return SanitizationResult(
            clean=False,
            findings=result.findings,
            sanitized_text=sanitized,
            scanned_at=result.scanned_at,
        )

    # ── Multi-field scanning ───────────────────────────────────

    def scan_fields(self, fields: dict[str, str]) -> SanitizationResult:
        """Scan multiple named fields and aggregate findings.

        Each field's findings are tagged with the field name as location.
        """
        now = datetime.now(timezone.utc)
        all_findings: list[SanitizationFinding] = []

        for field_name, value in fields.items():
            if not isinstance(value, str):
                continue
            result = self.scan(value, location=field_name)
            all_findings.extend(result.findings)

        return SanitizationResult(
            clean=len(all_findings) == 0,
            findings=all_findings,
            scanned_at=now,
        )
