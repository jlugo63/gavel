#!/usr/bin/env bash
# Submit governance chains PR to microsoft/agent-governance-toolkit.
# Prerequisites:
#   1. gh CLI installed and authenticated
#   2. Fork of microsoft/agent-governance-toolkit exists
#   3. Issue already created (run submit-agt-issue.sh first)
set -euo pipefail

UPSTREAM="microsoft/agent-governance-toolkit"
UPSTREAM_NAME="agent-governance-toolkit"
FORK_OWNER="jlugo63"
BRANCH="feat/governance-chains"
PKG_DIR="packages/gavel-governance"

# Capture source package absolute path BEFORE we cd into the fork clone.
SRC_PKG="$(pwd)/packages/gavel-governance"
if [ ! -d "${SRC_PKG}" ]; then
  echo "ERROR: source package not found at ${SRC_PKG}" >&2
  exit 1
fi

echo "=== Step 1: Clone fork ==="
if [ ! -d "${UPSTREAM_NAME}" ]; then
  gh repo fork "${UPSTREAM}" --clone --remote
fi
cd "${UPSTREAM_NAME}"
git fetch origin
git checkout main
git pull origin main

echo "=== Step 2: Create feature branch ==="
git checkout -B "${BRANCH}"

echo "=== Step 3: Copy package ==="
mkdir -p "${PKG_DIR}"
cp -r "${SRC_PKG}/src" "${PKG_DIR}/"
cp -r "${SRC_PKG}/tests" "${PKG_DIR}/"
cp -r "${SRC_PKG}/examples" "${PKG_DIR}/"
cp "${SRC_PKG}/pyproject.toml" "${PKG_DIR}/"
cp "${SRC_PKG}/README.md" "${PKG_DIR}/"

echo "=== Step 4: Commit ==="
git add "${PKG_DIR}"
git commit -m "feat(governance): add tamper-evident multi-principal governance chains

Add gavel-governance package providing:
- GovernanceArtifact: portable, self-verifiable governance decision records
- PolicyDecisionAdapter: emits dicts matching agentmesh.governance.policy
  .PolicyDecision exactly (allowed / action / reason / matched_rule /
  policy_name / metadata) — PolicyDecision(**adapter_output) works
- Hash-chain integrity verification (SHA-256, hashlib + json only)
- Separation of powers enforcement (structural, not configurable)
- 30 tests covering schema, adapter, AGT-literal coverage, round-trip,
  tamper detection, and a mirror test guarding against upstream drift

Only dependency: pydantic>=2.0. Fully typed (py.typed marker included).
No runtime dependency on agent-mesh — consumers construct PolicyDecision
from the returned dict."

echo "=== Step 5: Push and create PR ==="
git push -u origin "${BRANCH}"

PR_BODY=$(cat <<'PREOF'
## Summary

- Adds `packages/gavel-governance/` — a self-contained package providing tamper-evident, multi-principal governance chains on top of AGT's existing policy evaluation.
- `PolicyDecisionAdapter` emits dicts that construct directly into `agentmesh.governance.policy.PolicyDecision` — `allowed` / `action` / `reason` / `matched_rule` / `policy_name` / `metadata`.
- `action` is always within AGT's literal set (`allow` / `deny` / `require_approval` / `warn` / `log`). Validated by a mirror-schema test guarding against upstream drift.
- Separation of powers (proposer ≠ reviewer ≠ approver) enforced structurally at artifact-build time, not by policy configuration.
- Independent verification: any system can verify a governance artifact with only `hashlib` and `json` — no runtime dependency on this package, AGT, or Gavel.

## Scope

- New files only. No existing file is modified.
- `packages/gavel-governance/` is fully self-contained:
  - `src/gavel_governance/` — typed library (`py.typed` marker included)
  - `tests/` — 30 unit tests
  - `examples/quickstart.py` — runnable demo with no external dependencies
  - `pyproject.toml` — builds a wheel with only `pydantic>=2.0` as a runtime dep

## Test plan

- [x] `pytest packages/gavel-governance/tests -v` — 30 tests pass
- [x] `python packages/gavel-governance/examples/quickstart.py` — demo runs end-to-end, prints an AGT-shaped PolicyDecision dict
- [x] Mirror schema test (`test_decision_dict_accepted_by_agt_shape`) constructs a pydantic model field-for-field matching `agentmesh.governance.policy.PolicyDecision` and validates the adapter output against it
- [x] Wheel builds cleanly via `python -m build`
- [ ] Project CI (Python 3.10 / 3.11 / 3.12 matrix) passes on PR
- [ ] CLA bot check passes

## Related

Issue: #<issue-number-from-submit-agt-issue.sh>

🤖 Generated with [Claude Code](https://claude.com/claude-code)
PREOF
)

gh pr create \
  --repo "${UPSTREAM}" \
  --title "feat(governance): add tamper-evident multi-principal governance chains" \
  --body "${PR_BODY}" \
  --head "${FORK_OWNER}:${BRANCH}"

echo "Done. PR created."
