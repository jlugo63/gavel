"""
State Rollback — ATF R-4.

Before a governed action executes, the blast box captures a snapshot of
every file in the declared scope. If execution fails, or if a later
review flags a problem, the snapshot lets us:

  1. Verify nothing outside the declared scope was touched (integrity).
  2. Roll back the scope to its pre-execution state (recovery).
  3. Emit a compensating transaction record for audit.

Design:

- Snapshots are content-hashed (SHA-256) per file. We store the full
  file bytes only when the file is small enough; otherwise we keep the
  hash + size + path and decline rollback for that entry (explicit
  failure beats silent lossy recovery).

- Snapshot records are immutable Pydantic models. The "restore" step
  returns a CompensatingAction describing what was rolled back, rather
  than mutating the snapshot.

- Nothing here is Docker-specific. The blast box can call into this
  module regardless of the underlying execution ring.

Failure modes we accept:
- Binary files larger than the configured max stay "hash-only" and
  cannot be rolled back. The audit event records this gap explicitly
  so it's visible to reviewers.
- If a file is deleted that didn't exist in the snapshot, the rollback
  removes it but records the event as "compensating_delete".
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


# ── Snapshot primitives ────────────────────────────────────────

_DEFAULT_MAX_BYTES = 256 * 1024  # 256 KiB per-file cap for full capture


class FileSnapshot(BaseModel):
    """Content-addressed snapshot of a single file."""

    path: str
    sha256: str
    size: int
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Full bytes are captured only when under the size cap. Larger
    # files record hash + size only — rollback is declined for them.
    content_b64: Optional[str] = None
    captured_full: bool = False


class SnapshotManifest(BaseModel):
    """The full set of files snapshotted for one chain execution."""

    chain_id: str
    snapshot_id: str
    files: dict[str, FileSnapshot] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def manifest_hash(self) -> str:
        """Hash over (path, sha256) pairs sorted by path."""
        h = hashlib.sha256()
        for path in sorted(self.files):
            f = self.files[path]
            h.update(path.encode("utf-8"))
            h.update(b"\x00")
            h.update(f.sha256.encode("utf-8"))
            h.update(b"\x00")
        return h.hexdigest()


# ── Compensating transaction ──────────────────────────────────

class CompensatingAction(BaseModel):
    """Record of a single rollback step for the audit trail."""

    path: str
    kind: str  # "restore" | "delete_added" | "declined_oversize" | "missing_content"
    detail: str = ""
    sha256_before: Optional[str] = None
    sha256_after: Optional[str] = None


class RollbackReport(BaseModel):
    """Full record of a rollback attempt, suitable for chain append."""

    chain_id: str
    snapshot_id: str
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trigger_reason: str = ""
    actions: list[CompensatingAction] = Field(default_factory=list)
    fully_restored: bool = False
    declined: list[str] = Field(default_factory=list)


# ── Snapshotter ────────────────────────────────────────────────

def _hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _iter_scope(scope_paths: list[str], root: Path) -> list[Path]:
    """Enumerate files under every declared scope path.

    Scope entries may be concrete files or directories relative to
    `root`. Nonexistent entries are silently skipped — the snapshot
    records absence as empty rather than failing.
    """
    out: list[Path] = []
    for entry in scope_paths:
        p = (root / entry).resolve()
        if not p.exists():
            continue
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            for sub in p.rglob("*"):
                if sub.is_file():
                    out.append(sub)
    return out


class Snapshotter:
    """Captures and restores content snapshots for rollback.

    The snapshotter is stateless apart from the per-chain manifest store.
    Callers drive it from the blast box: snapshot before execution,
    restore on failure.
    """

    def __init__(self, max_bytes_per_file: int = _DEFAULT_MAX_BYTES):
        self._max_bytes = max_bytes_per_file
        self._manifests: dict[str, SnapshotManifest] = {}

    def snapshot(
        self,
        chain_id: str,
        scope_paths: list[str],
        root: Path | str = ".",
    ) -> SnapshotManifest:
        """Capture a manifest for the declared scope paths."""
        import base64

        root_path = Path(root).resolve()
        snap_id = f"snap-{chain_id}-{int(datetime.now(timezone.utc).timestamp())}"
        manifest = SnapshotManifest(chain_id=chain_id, snapshot_id=snap_id)

        for file_path in _iter_scope(scope_paths, root_path):
            try:
                size = file_path.stat().st_size
            except OSError:
                continue

            rel = str(file_path.relative_to(root_path)) if file_path.is_absolute() else str(file_path)

            if size <= self._max_bytes:
                data = file_path.read_bytes()
                snap = FileSnapshot(
                    path=rel,
                    sha256=_hash_bytes(data),
                    size=size,
                    content_b64=base64.b64encode(data).decode("ascii"),
                    captured_full=True,
                )
            else:
                # Streamed hash for oversize files
                h = hashlib.sha256()
                with file_path.open("rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)
                snap = FileSnapshot(
                    path=rel,
                    sha256=h.hexdigest(),
                    size=size,
                    content_b64=None,
                    captured_full=False,
                )

            manifest.files[rel] = snap

        self._manifests[chain_id] = manifest
        return manifest

    def get(self, chain_id: str) -> Optional[SnapshotManifest]:
        return self._manifests.get(chain_id)

    def rollback(
        self,
        chain_id: str,
        reason: str,
        root: Path | str = ".",
        files_added_by_action: list[str] | None = None,
    ) -> RollbackReport:
        """Restore the snapshot for `chain_id`. Returns a RollbackReport."""
        import base64

        manifest = self._manifests.get(chain_id)
        if manifest is None:
            return RollbackReport(
                chain_id=chain_id,
                snapshot_id="",
                trigger_reason=f"no snapshot for chain_id={chain_id}: {reason}",
                fully_restored=False,
            )

        root_path = Path(root).resolve()
        actions: list[CompensatingAction] = []
        declined: list[str] = []

        # Step 1: Delete any files the action created that weren't in
        # the snapshot. These are explicit compensating deletes.
        for added in files_added_by_action or []:
            if added in manifest.files:
                continue
            p = (root_path / added).resolve()
            try:
                if p.exists() and p.is_file():
                    p.unlink()
                    actions.append(
                        CompensatingAction(
                            path=added,
                            kind="delete_added",
                            detail="removed file created during execution",
                        )
                    )
            except OSError as e:
                actions.append(
                    CompensatingAction(
                        path=added,
                        kind="delete_added",
                        detail=f"failed to delete: {e}",
                    )
                )

        # Step 2: Restore every file the manifest captured.
        for path, snap in manifest.files.items():
            full_path = (root_path / path).resolve()
            if not snap.captured_full or snap.content_b64 is None:
                declined.append(path)
                actions.append(
                    CompensatingAction(
                        path=path,
                        kind="declined_oversize",
                        detail=(
                            f"file >{self._max_bytes} bytes at snapshot time; "
                            f"rollback declined to avoid lossy restore"
                        ),
                        sha256_before=snap.sha256,
                    )
                )
                continue

            before_hash: Optional[str] = None
            if full_path.exists():
                try:
                    before_hash = _hash_bytes(full_path.read_bytes())
                except OSError:
                    before_hash = None

            try:
                full_path.parent.mkdir(parents=True, exist_ok=True)
                full_path.write_bytes(base64.b64decode(snap.content_b64))
                actions.append(
                    CompensatingAction(
                        path=path,
                        kind="restore",
                        detail="restored from snapshot",
                        sha256_before=before_hash,
                        sha256_after=snap.sha256,
                    )
                )
            except OSError as e:
                actions.append(
                    CompensatingAction(
                        path=path,
                        kind="missing_content",
                        detail=f"restore failed: {e}",
                        sha256_before=before_hash,
                    )
                )
                declined.append(path)

        fully_restored = not declined

        return RollbackReport(
            chain_id=chain_id,
            snapshot_id=manifest.snapshot_id,
            trigger_reason=reason,
            actions=actions,
            fully_restored=fully_restored,
            declined=declined,
        )

    def verify_untouched(self, chain_id: str, root: Path | str = ".") -> list[str]:
        """Return paths that have changed since the snapshot was taken."""
        manifest = self._manifests.get(chain_id)
        if manifest is None:
            return []

        root_path = Path(root).resolve()
        drifted: list[str] = []
        for path, snap in manifest.files.items():
            full = (root_path / path).resolve()
            if not full.exists():
                drifted.append(path)
                continue
            try:
                data = full.read_bytes()
            except OSError:
                drifted.append(path)
                continue
            if _hash_bytes(data) != snap.sha256:
                drifted.append(path)
        return drifted
