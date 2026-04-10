#!/usr/bin/env bash
# Submit governance chains PR to microsoft/agent-governance-toolkit.
# Prerequisites:
#   1. gh CLI installed and authenticated
#   2. Fork of microsoft/agent-governance-toolkit exists
#   3. Issue already created (run submit-agt-issue.sh first)
set -euo pipefail

UPSTREAM="microsoft/agent-governance-toolkit"
FORK_OWNER="jlugo63"
BRANCH="feat/governance-chains"
PKG_DIR="packages/gavel-governance"

echo "=== Step 1: Clone fork ==="
if [ ! -d "agt-fork" ]; then
  gh repo fork "${UPSTREAM}" --clone --remote
  cd agent-governance-toolkit
else
  cd agt-fork
  git fetch origin
  git checkout main
  git pull origin main
fi

echo "=== Step 2: Create feature branch ==="
git checkout -b "${BRANCH}"

echo "=== Step 3: Copy package ==="
mkdir -p "${PKG_DIR}"
cp -r "../packages/gavel-governance/src" "${PKG_DIR}/"
cp -r "../packages/gavel-governance/tests" "${PKG_DIR}/"
cp -r "../packages/gavel-governance/examples" "${PKG_DIR}/"
cp "../packages/gavel-governance/pyproject.toml" "${PKG_DIR}/"
cp "../packages/gavel-governance/README.md" "${PKG_DIR}/"

echo "=== Step 4: Commit ==="
git add "${PKG_DIR}"
git commit -m "feat(governance-chains): add tamper-evident multi-principal decision workflows

Add gavel-governance package providing:
- GovernanceArtifact: portable, self-verifiable governance decision records
- PolicyDecisionAdapter: maps governance outcomes to AGT PolicyDecision schema
- Hash-chain integrity verification (SHA-256)
- Separation of powers enforcement (structural, not configurable)
- 28 tests covering schema, adapter, verification, and roundtrip

Only dependency: pydantic>=2.0. Fully typed (py.typed marker included)."

echo "=== Step 5: Push and create PR ==="
git push -u origin "${BRANCH}"

PR_BODY=$(cat <<'PREOF'
## Summary

- Add `packages/gavel-governance/` — constitutional governance chains with AGT PolicyDecision output
- GovernanceArtifact schema: portable, independently verifiable decision records
- PolicyDecisionAdapter: verdict/reason/matched_rule/metadata mapping
- Separation of powers enforced structurally (proposer ≠ reviewer ≠ approver)
- 28 tests, typed public APIs, zero runtime dependencies beyond pydantic

## Test plan

- [x] `pytest tests/ -v` — 28 tests pass
- [x] `python examples/quickstart.py` — demo runs end-to-end
- [x] Package builds: `python -m build` produces valid wheel
- [ ] CI passes on PR

🤖 Generated with [Claude Code](https://claude.com/claude-code)
PREOF
)

gh pr create \
  --repo "${UPSTREAM}" \
  --title "feat(governance-chains): tamper-evident multi-principal decision workflows" \
  --body "${PR_BODY}" \
  --head "${FORK_OWNER}:${BRANCH}"

echo "Done. PR created."
