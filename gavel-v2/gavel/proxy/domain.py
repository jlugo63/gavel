"""
Domain matching for AI API traffic detection.

Part of Gavel -- Constitutional governance for AI agents (EU AI Act).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from gavel.proxy.config import DomainEntry, _default_ai_domains


class DomainMatcher:
    """Match request hosts against configured AI API domain patterns."""

    def __init__(self, domains: list[DomainEntry] | None = None):
        self._domains = domains or _default_ai_domains()
        self._compiled: list[tuple[re.Pattern, str]] = []
        for entry in self._domains:
            regex = self._glob_to_regex(entry.pattern)
            self._compiled.append((re.compile(regex, re.IGNORECASE), entry.label or entry.pattern))

    @staticmethod
    def _glob_to_regex(glob: str) -> str:
        """Convert a domain glob (e.g. ``*.docker.com``) to a regex."""
        escaped = re.escape(glob).replace(r"\*", r"[a-zA-Z0-9\-\.]*")
        return f"^{escaped}$"

    def match(self, host: str) -> tuple[bool, str]:
        """Returns ``(is_ai_domain, label)`` for a given host string."""
        host_no_port = host.split(":")[0] if ":" in host else host
        for pattern, label in self._compiled:
            if pattern.match(host) or pattern.match(host_no_port):
                return True, label
        return False, ""

    @classmethod
    def from_yaml(cls, path: str | Path) -> DomainMatcher:
        """Load domain config from a YAML file.

        Expected format::

            ai_domains:
              - pattern: "api.openai.com"
                label: "OpenAI API"
        """
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        raw = data.get("ai_domains", data if isinstance(data, list) else [])
        domains = [DomainEntry(**d) if isinstance(d, dict) else d for d in raw]
        return cls(domains)
