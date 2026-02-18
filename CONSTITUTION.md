# Gavel Constitution
Version: 1.0.0 (Foundation Sprint)

## I. Governance Invariants
1. **Immutable History:** No event logged to the Audit Spine shall be modified or deleted.
2. **Authority Decoupling:** Agents cannot modify the code within the `/governance` or `/policy` directories.
3. **Tiered Autonomy:** No action categorized as "Tier 2" or higher shall be executed without a valid Human Approval Token.

## II. Operational Constraints
- No command shall utilize `sudo` or `chmod 777`.
- All external API calls must be proxied through the Governance Gateway for intent-logging.