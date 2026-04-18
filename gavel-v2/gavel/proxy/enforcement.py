"""
Enforcement ledger -- append-only, hash-chained event log.

Part of Gavel -- Constitutional governance for AI agents (EU AI Act).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

log = logging.getLogger("gavel.proxy")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ProxyEnforcementAction(str, Enum):
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"

# Backward-compatible alias
EnforcementAction = ProxyEnforcementAction


class LedgerEntry(BaseModel):
    """Append-only, hash-chained enforcement event."""

    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source_agent: str = ""
    destination_domain: str = ""
    method: str = ""
    path: str = ""
    action: ProxyEnforcementAction = ProxyEnforcementAction.BLOCKED
    reason: str = ""
    token_id: str = ""
    prev_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self, prev: str = "") -> str:
        """SHA-256 over deterministic JSON of the entry fields (excluding entry_hash)."""
        payload = self.model_dump(exclude={"entry_hash"})
        payload["prev_hash"] = prev
        raw = json.dumps(payload, sort_keys=True, default=str).encode()
        return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Enforcement Ledger (append-only, hash-chained)
# ---------------------------------------------------------------------------


class EnforcementLedger:
    """
    Append-only hash-chained log.  Each entry's hash covers the previous
    entry's hash, making the ledger tamper-evident -- the same principle
    used by ``gavel.chain.GovernanceChain``.
    """

    def __init__(self, path: Path | None = None):
        self._path = path or Path("enforcement_ledger.jsonl")
        self._last_hash: str = "genesis"
        self._lock = asyncio.Lock()
        self._restore_chain_tip()

    def _restore_chain_tip(self) -> None:
        """Read the last line of an existing ledger to resume the hash chain."""
        if not self._path.exists():
            return
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                last_line = ""
                for line in fh:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
                if last_line:
                    data = json.loads(last_line)
                    self._last_hash = data.get("entry_hash", "genesis")
        except (OSError, json.JSONDecodeError, KeyError):
            log.warning("Could not restore ledger chain tip; starting fresh chain.")

    async def append(self, entry: LedgerEntry) -> LedgerEntry:
        async with self._lock:
            entry.prev_hash = self._last_hash
            entry.entry_hash = entry.compute_hash(self._last_hash)
            self._last_hash = entry.entry_hash

            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(entry.model_dump_json() + "\n")

            log.info(
                "LEDGER %s | %s %s%s | agent=%s token=%s reason=%s hash=%s",
                entry.action.value,
                entry.method,
                entry.destination_domain,
                entry.path,
                entry.source_agent or "-",
                entry.token_id or "-",
                entry.reason,
                entry.entry_hash[:16],
            )
            return entry

    async def verify_integrity(self) -> tuple[bool, int, list[str]]:
        """Walk the full ledger and verify every hash link."""
        if not self._path.exists():
            return True, 0, []
        errors: list[str] = []
        prev_hash = "genesis"
        count = 0
        with open(self._path, "r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                count += 1
                try:
                    data = json.loads(raw)
                    entry = LedgerEntry(**data)
                    expected = entry.compute_hash(prev_hash)
                    if entry.entry_hash != expected:
                        errors.append(
                            f"Line {lineno}: hash mismatch "
                            f"(expected {expected[:16]}..., got {entry.entry_hash[:16]}...)"
                        )
                    if entry.prev_hash != prev_hash:
                        errors.append(
                            f"Line {lineno}: prev_hash mismatch "
                            f"(expected {prev_hash[:16]}..., got {entry.prev_hash[:16]}...)"
                        )
                    prev_hash = entry.entry_hash
                except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
                    errors.append(f"Line {lineno}: parse error -- {exc}")
        return len(errors) == 0, count, errors
