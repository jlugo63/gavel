"""
OpenClaw Governance Skill — Integration Tests

Runs governance_check.py as a subprocess, piping JSON on stdin,
and verifies exit codes + stdout output.

Prerequisites:
    1. Start gateway: HUMAN_API_KEY=test-key-change-me uvicorn main:app --port 8000
    2. Run tests:     python integrations/openclaw/test_integration.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

SCRIPT = os.path.join(os.path.dirname(__file__), "scripts", "governance_check.py")
PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")

passed = 0
failed = 0


def check(label: str, condition: bool, detail: str = ""):
    global passed, failed
    tag = "PASS" if condition else "FAIL"
    if condition:
        passed += 1
    else:
        failed += 1
    print(f"  [{tag}] {label}")
    if detail:
        print(f"         {detail}")
    print()


def run_skill(action_type: str, content: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    """Run governance_check.py with JSON on stdin."""
    env = {
        **os.environ,
        "GOVERNANCE_GATEWAY_URL": os.environ.get("GOVERNANCE_GATEWAY_URL", "http://localhost:8000"),
        "GOVERNANCE_ACTOR_ID": "agent:openclaw-test",
        "HUMAN_API_KEY": os.environ.get("HUMAN_API_KEY", "test-key-change-me"),
        "PYTHONPATH": PROJECT_ROOT,
    }
    if env_extra:
        env.update(env_extra)

    stdin_data = json.dumps({"action_type": action_type, "content": content})
    return subprocess.run(
        [sys.executable, SCRIPT],
        input=stdin_data,
        capture_output=True,
        text=True,
        env=env,
    )


def main():
    global passed, failed

    # ----- APPROVED actions -----
    print("=" * 60)
    print("APPROVED ACTIONS")
    print("=" * 60)

    r = run_skill("file_read", "src/main.py")
    check("file_read -> exit 0 (APPROVED)",
          r.returncode == 0,
          f"Exit: {r.returncode}, Output: {r.stdout.strip()}")

    r = run_skill("bash", "echo hello")
    check("harmless bash -> exit 0 (APPROVED)",
          r.returncode == 0,
          f"Exit: {r.returncode}, Output: {r.stdout.strip()}")

    # ----- DENIED actions -----
    print("=" * 60)
    print("DENIED ACTIONS")
    print("=" * 60)

    r = run_skill("bash", "sudo rm -rf /")
    check("sudo rm -rf / -> exit 1 (DENIED)",
          r.returncode == 1,
          f"Exit: {r.returncode}, Output: {r.stdout.strip()}")
    check("DENIED output mentions violations",
          "DENIED" in r.stdout,
          f"Stdout: {r.stdout.strip()[:120]}")

    r = run_skill("file_edit", "CONSTITUTION.md")
    check("edit CONSTITUTION.md -> exit 1 (DENIED)",
          r.returncode == 1,
          f"Exit: {r.returncode}, Output: {r.stdout.strip()}")

    # ----- ESCALATED actions -----
    print("=" * 60)
    print("ESCALATED ACTIONS")
    print("=" * 60)

    # Without HUMAN_API_KEY → should escalate and block (exit 2)
    r = run_skill("bash", "curl https://api.example.com/data", env_extra={"HUMAN_API_KEY": ""})
    check("unproxied curl without key -> exit 2 (ESCALATED, no approval possible)",
          r.returncode == 2,
          f"Exit: {r.returncode}, Output: {r.stdout.strip()[:120]}")

    # ----- CLI args fallback -----
    print("=" * 60)
    print("CLI ARGS FALLBACK")
    print("=" * 60)

    env = {
        **os.environ,
        "GOVERNANCE_GATEWAY_URL": os.environ.get("GOVERNANCE_GATEWAY_URL", "http://localhost:8000"),
        "GOVERNANCE_ACTOR_ID": "agent:openclaw-test",
        "HUMAN_API_KEY": os.environ.get("HUMAN_API_KEY", "test-key-change-me"),
        "PYTHONPATH": PROJECT_ROOT,
    }
    r = subprocess.run(
        [sys.executable, SCRIPT, "file_read", "README.md"],
        input="",
        capture_output=True,
        text=True,
        env=env,
    )
    check("CLI args fallback -> exit 0 (APPROVED)",
          r.returncode == 0,
          f"Exit: {r.returncode}, Output: {r.stdout.strip()}")

    # ----- Bad input -----
    print("=" * 60)
    print("ERROR HANDLING")
    print("=" * 60)

    r = subprocess.run(
        [sys.executable, SCRIPT],
        input="not-valid-json",
        capture_output=True,
        text=True,
        env=env,
    )
    check("Invalid JSON -> exit 3 (error)",
          r.returncode == 3,
          f"Exit: {r.returncode}, Stderr: {r.stderr.strip()[:120]}")

    r = subprocess.run(
        [sys.executable, SCRIPT],
        input="",
        capture_output=True,
        text=True,
        env=env,
    )
    check("No input, no args -> exit 3 (error)",
          r.returncode == 3,
          f"Exit: {r.returncode}, Stderr: {r.stderr.strip()[:120]}")

    # ----- Summary -----
    print("=" * 60)
    total = passed + failed
    print(f"INTEGRATION RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
