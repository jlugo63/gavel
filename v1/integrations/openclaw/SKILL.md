---
name: gavel-governance
description: Submit proposed actions to the Gavel governance gateway for policy evaluation before executing shell commands, file modifications, or external API calls.
metadata: {"openclaw":{"requires":{"env":["GOVERNANCE_GATEWAY_URL","HUMAN_API_KEY"]},"primaryEnv":"HUMAN_API_KEY"}}
---

## Gavel Governance Check

You are operating under a **governance policy**. Before executing any action that modifies the system, you MUST submit it to the Gavel governance gateway for approval.

### Actions that require governance approval

- Any shell command (`bash`, `exec`, `shell`)
- Any file write, file edit, or file delete
- Any external API call (`curl`, `wget`, `http`)
- Any package installation or dependency change
- Any deployment, scaling, or infrastructure change

### Required workflow

**Step 1: Submit a proposal before acting.**

For every action listed above, call the governance gateway FIRST:

```bash
curl -s -X POST "${GOVERNANCE_GATEWAY_URL:-http://localhost:8000}/propose" \
  -H "Content-Type: application/json" \
  -d '{"actor_id": "agent:openclaw", "action_type": "ACTION_TYPE_HERE", "content": "THE_EXACT_COMMAND_OR_OPERATION"}'
```

Replace `ACTION_TYPE_HERE` with one of: `bash`, `file_write`, `file_edit`, `file_read`, `api_call`.
Replace `THE_EXACT_COMMAND_OR_OPERATION` with the literal command or file path you intend to act on.

**Step 2: Read the `decision` field from the JSON response.**

- **`APPROVED`** -- Proceed with the action normally.
- **`DENIED`** -- Do NOT execute the action. Report the `violations` array to the user. Explain which constitutional provisions were violated and why.
- **`ESCALATED`** -- Do NOT execute the action yet. Tell the user this action requires human approval. Show them the `risk_score` and the `intent_event_id`. Wait for the user to decide.

**Step 3: If the user approves an ESCALATED action, record their approval:**

```bash
curl -s -X POST "${GOVERNANCE_GATEWAY_URL:-http://localhost:8000}/approve" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${HUMAN_API_KEY}" \
  -d '{"intent_event_id": "THE_INTENT_ID", "policy_event_id": "THE_POLICY_ID"}'
```

Then proceed with the original action.

### Rules

1. **NEVER skip governance check.** Every covered action must be proposed first.
2. **NEVER execute a DENIED action.** No exceptions, no workarounds.
3. **Fail closed.** If the gateway is unreachable or returns an error, do NOT execute the action. Tell the user the governance gateway is unavailable.
4. **Be transparent.** Always tell the user what decision the gateway returned and why.
