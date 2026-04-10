#!/usr/bin/env bash
# Submit an ECOSYSTEM.md entry to massivescale-ai/agentic-trust-framework.
# Prerequisites:
#   1. gh CLI installed and authenticated
#   2. You agree to add the Gavel entry exactly as it appears in
#      docs/atf-ecosystem-entry.md
set -euo pipefail

UPSTREAM="massivescale-ai/agentic-trust-framework"
UPSTREAM_NAME="agentic-trust-framework"
FORK_OWNER="jlugo63"
BRANCH="ecosystem/add-gavel"

ENTRY_FILE="$(pwd)/docs/atf-ecosystem-entry.md"
if [ ! -f "${ENTRY_FILE}" ]; then
  echo "ERROR: entry file not found at ${ENTRY_FILE}" >&2
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

echo "=== Step 3: Append Gavel entry to ECOSYSTEM.md ==="
# Strip the YAML-ish header from our local entry file — keep only the
# markdown starting at "## Gavel".
python - "${ENTRY_FILE}" ECOSYSTEM.md <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as f:
    lines = f.readlines()
# Find the "## Gavel" header and keep everything from there onward.
start = next(i for i, line in enumerate(lines) if line.strip().startswith("## Gavel"))
entry = "".join(lines[start:]).rstrip() + "\n"
with open(dst, "a", encoding="utf-8") as f:
    f.write("\n")
    f.write(entry)
print(f"Appended {len(entry.splitlines())} lines to {dst}")
PY

echo "=== Step 4: Commit ==="
git add ECOSYSTEM.md
git commit -m "ecosystem: add Gavel

Add Gavel — constitutional governance layer for autonomous AI agents,
built on Microsoft's Agent Governance Toolkit. 351 tests, MIT-licensed,
Python 3.11+. Independently convergent implementation of all five ATF
core elements. See the entry for the full five-row ATF-element table."

echo "=== Step 5: Push and create PR ==="
git push -u origin "${BRANCH}"

PR_BODY=$(cat <<'PREOF'
## Summary

Adds an entry for **Gavel** to `ECOSYSTEM.md`. Gavel is an MIT-licensed,
Python 3.11+ constitutional governance layer built on Microsoft's Agent
Governance Toolkit. The entry follows the existing Microsoft entry's
format exactly (org/relationship/repo header, ≤10-line prose paragraph,
five-row ATF-element table).

## How Gavel relates to ATF

Gavel is an independently convergent implementation of all five ATF
core elements:

- **Identity** — Ed25519 DIDs at enrollment, governance tokens, structural separation of powers (proposer ≠ reviewer ≠ approver)
- **Behavior** — Tiered autonomy, risk scoring, constitutional invariants, SLA-based liveness auto-deny
- **Data Governance** — Scope-compliance, secret detection in evidence review, tamper-evident decision artifacts
- **Segmentation** — Sandboxed blast-box execution, Cedar policy enforcement, default-deny network proxy for AI API traffic
- **Incident Response** — Append-only audit ledger, EU AI Act Article 15-style incident lifecycle with 2-day/15-day deadline tracking

## Test plan

- [x] Entry is ≤10 prose lines, matches the Microsoft entry's structure
- [x] Five-row ATF element table
- [x] Links resolve (jlugo63/gavel, CSA-ATF-PROPOSAL reference for comparison)
- [x] Gavel repo is public, MIT-licensed, and ships a runnable quickstart

🤖 Generated with [Claude Code](https://claude.com/claude-code)
PREOF
)

gh pr create \
  --repo "${UPSTREAM}" \
  --title "ecosystem: add Gavel" \
  --body "${PR_BODY}" \
  --head "${FORK_OWNER}:${BRANCH}"

echo "Done. PR created."
