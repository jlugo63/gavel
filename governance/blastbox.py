"""
Blast Box — Docker-based sandbox execution
Constitutional Reference: SS II — Blast Box sandbox execution

Runs agent-proposed commands inside isolated, resource-limited Docker
containers.  The workspace is snapshotted before and after execution so
callers can produce a deterministic diff of side-effects.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class BlastBoxConfig:
    """Tunable limits for a single sandbox run."""
    image: str = "python:3.12-slim"
    memory_limit: str = "256m"
    cpu_limit: float = 1.0
    timeout_seconds: int = 30
    network_mode: str = "none"


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class BlastBoxResult:
    """Outcome of a single sandbox execution."""
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    workspace_diff: dict = field(default_factory=lambda: {
        "added": {},
        "modified": {},
        "deleted": {},
        "unchanged": {},
    })
    timed_out: bool = False
    oom_killed: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MAX_OUTPUT_BYTES = 64 * 1024  # 64 KB cap per stream


def check_docker_available() -> bool:
    """Return True if the Docker daemon is reachable."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False
    except subprocess.TimeoutExpired:
        return False


def _hash_workspace(path: str) -> dict[str, str]:
    """Walk *path* and return ``{relative_path: sha256_hex}``."""
    hashes: dict[str, str] = {}
    for dirpath, _dirs, filenames in os.walk(path):
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, path)
            # Normalise to forward slashes for cross-platform consistency
            rel = rel.replace("\\", "/")
            h = hashlib.sha256()
            try:
                with open(full, "rb") as fh:
                    for chunk in iter(lambda: fh.read(8192), b""):
                        h.update(chunk)
                hashes[rel] = h.hexdigest()
            except OSError:
                # Symlink target gone, permission denied, etc. — skip
                continue
    return hashes


def _compute_workspace_diff(
    before: dict[str, str],
    after: dict[str, str],
) -> dict:
    """Compare two workspace snapshots and classify every file."""
    added: dict[str, str] = {}
    modified: dict[str, str] = {}
    deleted: dict[str, str] = {}
    unchanged: dict[str, str] = {}

    for name, digest in after.items():
        if name not in before:
            added[name] = digest
        elif before[name] != digest:
            modified[name] = digest
        else:
            unchanged[name] = digest

    for name, digest in before.items():
        if name not in after:
            deleted[name] = digest

    return {
        "added": added,
        "modified": modified,
        "deleted": deleted,
        "unchanged": unchanged,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_in_blastbox(
    command: str,
    workspace_dir: str | None = None,
    config: BlastBoxConfig | None = None,
) -> BlastBoxResult:
    """Execute *command* inside a disposable Docker container.

    If *workspace_dir* is ``None`` a temporary directory is created and
    cleaned up automatically.  Otherwise the caller-supplied directory is
    bind-mounted at ``/workspace`` inside the container.
    """
    if config is None:
        config = BlastBoxConfig()

    cleanup_workspace = False
    if workspace_dir is None:
        workspace_dir = tempfile.mkdtemp(prefix="blastbox_")
        cleanup_workspace = True

    # -- Pre-execution snapshot -------------------------------------------
    before = _hash_workspace(workspace_dir)

    # -- Build docker run command -----------------------------------------
    # For OOM detection we need the container to stick around, so we do NOT
    # use --rm.  Instead we inspect after execution and then remove.
    container_name = f"blastbox-{os.getpid()}-{int(time.monotonic() * 1000)}"

    docker_cmd = [
        "docker", "run",
        "--name", container_name,
        "--network", config.network_mode,
        "--memory", config.memory_limit,
        "--cpus", str(config.cpu_limit),
        "--read-only",
        "--tmpfs", "/tmp",
        "-v", f"{os.path.abspath(workspace_dir)}:/workspace",
        "-w", "/workspace",
        config.image,
        "sh", "-c", command,
    ]

    # -- Execute ----------------------------------------------------------
    timed_out = False
    oom_killed = False
    t0 = time.monotonic()

    try:
        proc = subprocess.run(
            docker_cmd,
            capture_output=True,
            timeout=config.timeout_seconds,
        )
        exit_code = proc.returncode
        stdout_raw = proc.stdout
        stderr_raw = proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = -1
        stdout_raw = exc.stdout or b""
        stderr_raw = exc.stderr or b""
        # Kill the still-running container
        subprocess.run(
            ["docker", "kill", container_name],
            capture_output=True,
            timeout=10,
        )

    duration_ms = int((time.monotonic() - t0) * 1000)

    # -- Truncate output --------------------------------------------------
    stdout = stdout_raw[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    stderr = stderr_raw[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

    # -- OOM detection ----------------------------------------------------
    if exit_code == 137:
        try:
            inspect = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.OOMKilled}}", container_name],
                capture_output=True,
                timeout=10,
            )
            if inspect.stdout.strip().lower() == b"true":
                oom_killed = True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # -- Clean up container -----------------------------------------------
    try:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # -- Post-execution snapshot ------------------------------------------
    after = _hash_workspace(workspace_dir)
    workspace_diff = _compute_workspace_diff(before, after)

    # -- Clean up temp workspace if we created it -------------------------
    if cleanup_workspace:
        try:
            import shutil
            shutil.rmtree(workspace_dir, ignore_errors=True)
        except OSError:
            pass

    return BlastBoxResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        workspace_diff=workspace_diff,
        timed_out=timed_out,
        oom_killed=oom_killed,
    )
