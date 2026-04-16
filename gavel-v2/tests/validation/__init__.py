"""
Gavel Validation Suite.

These are scenario-level, adversarial validation tests that prove production
capability end-to-end. They complement the unit test suite under `tests/` but
are organized by scenario rather than by module.

Wave gating (execute in order; halt on failure):

  Wave 1  — Deterministic local:   V3, V4, V5, V10       (red_team + compliance)
  Wave 2  — Adversarial logic:     V2, V6, V8            (red_team)
  Wave 3  — Distributed systems:   V7, V9                (gated on Wave 1+2 green)
  Wave 4  — Live LLM integration:  V1                    (gated on Wave 1+2+3 green)

Run: `pytest tests/validation/ -v` or `scripts/run-validation.sh`
"""
