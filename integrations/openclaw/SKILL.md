---
name: governance-check
description: Submit proposed actions to the Constitutional AI Governance Gateway for policy evaluation before execution.
version: 1.0.0
author: jlugo63
triggers:
  - before_bash
  - before_file_write
  - before_file_edit
scripts:
  - scripts/governance_check.py
env:
  GOVERNANCE_GATEWAY_URL: http://localhost:8000
  GOVERNANCE_ACTOR_ID: agent:openclaw
---

# Governance Check Skill

This skill enforces the **Constitutional AI Control Plane** by intercepting
proposed actions and submitting them to the Governance Gateway for policy
evaluation *before* execution.

## How It Works

1. **Intercept** — When OpenClaw is about to run a bash command, write a file,
   or edit a file, this skill fires first.
2. **Propose** — The action type and content are sent to the Governance Gateway
   via `POST /propose`.
3. **Decide** — Based on the gateway's response:
   - **APPROVED** → The action proceeds normally.
   - **ESCALATED** → The action is paused and the user is prompted to approve
     or deny. If approved, the skill calls `POST /approve` to record consent.
   - **DENIED** → The action is blocked with an explanation of which
     constitutional provisions were violated.

## Requirements

- Python 3.11+
- `governance_sdk` package (included in this repository)
- A running Governance Gateway at the configured `GOVERNANCE_GATEWAY_URL`

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GOVERNANCE_GATEWAY_URL` | `http://localhost:8000` | Base URL of the Governance Gateway |
| `GOVERNANCE_ACTOR_ID` | `agent:openclaw` | Actor identity for audit logging |
| `HUMAN_API_KEY` | *(none)* | Bearer token for approving escalated proposals |
