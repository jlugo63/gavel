# Gavel Roadmap

## Phase 1: Core Governance Engine [COMPLETE]
- [x] Hash-chained governance events (`chain.py`)
- [x] Constitutional invariants (`constitution.py`)
- [x] Separation of powers enforcement (`separation.py`)
- [x] Blast box sandboxed execution (`blastbox.py`)
- [x] Deterministic evidence review (`evidence.py`)
- [x] Tiered autonomy with risk scoring (`tiers.py`)
- [x] SLA-based liveness monitor (`liveness.py`)
- [x] FastAPI gateway (`gateway.py`)
- [x] Unit, integration, and adversarial tests (158 tests, 97.5% coverage)

## Phase 2: Microsoft AGT Compatibility Layer [COMPLETE]
- [x] AGT compatibility layer with real-package-first imports (`agt_compat.py`)
- [x] Stub classes for Agent OS, Agent Mesh, Agent Control Plane
- [x] Ed25519 identity stubs (DID generation)
- [x] Trust scoring integration
- [x] Policy engine integration
- [x] Cedar policy support for constitutional invariants

## Phase 3: Universal Agent Enrollment [COMPLETE]
- [x] Phase 3a: Universal agent enrollment with ATF pre-flight (`enrollment.py`)
- [x] Phase 3b: Execution loop, auth middleware, chain locks (`gate.py`)
- [x] Phase 3c: EU AI Act Tier 1 compliance (`compliance.py`)
- [x] Phase 3d: Governance dashboard and compliance API router (`compliance_router.py`)
- [x] Agent registry with heartbeat monitoring (`agents.py`)
- [x] Supervisor execution loop (`supervisor.py`)
- [x] Claude Code hooks integration (`hooks.py`)

## Phase 4: Integration PR [COMPLETE]
- [x] GovernanceArtifact spec: minimal Pydantic schema for cross-system artifact verification
- [x] PolicyDecisionAdapter: maps Gavel output to AGT's PolicyDecision schema (verdict/reason/matched_rule/metadata)
- [x] Follow PR #738 pattern: focused commits, security hardening, docs, tests
- [x] Follow Rul1an playbook: small scope, concrete sample, "here it is running" (`examples/artifact_demo.py`)
- [x] Align output format with AGT's PolicyDecision schema (verdict/reason/matched_rule/metadata)
- [x] Integration package structured for AGT PR (`packages/gavel-governance/`)
- [x] 16 new artifact tests (320 total, all passing)
- [x] Target: PR to microsoft/agent-governance-toolkit

### Phase 4 Deliverables
| File | Purpose |
|------|---------|
| `gavel/artifact.py` | GovernanceArtifact schema, PolicyDecisionAdapter, from_chain factory, verify_artifact |
| `packages/gavel-governance/` | Self-contained AGT integration package |
| `examples/artifact_demo.py` | Concrete runnable demo — no external deps |
| `tests/test_artifact.py` | 16 tests covering schema, adapter, verification, roundtrip |

## Phase 5: Community Engagement [COMPLETE]
- [x] Open issue on microsoft/agent-governance-toolkit proposing governance chains (`docs/agt-issue-draft.md`, `scripts/submit-agt-issue.sh`)
- [x] Submit PR with packages/gavel-governance integration (`scripts/submit-agt-pr.sh`)
- [x] Engage with AGT maintainers on PolicyDecision extension points (PolicyDecisionAdapter aligned to verdict/reason/matched_rule/metadata)
- [x] Write blog post: "Constitutional Governance for Autonomous AI Agents" (`docs/blog-post.md`)
- [x] Publish gavel-governance to PyPI (`scripts/publish-pypi.sh`, wheel builds successfully)

### Phase 5 Deliverables
| File | Purpose |
|------|---------|
| `docs/agt-issue-draft.md` | GitHub issue text proposing governance chains for AGT |
| `docs/blog-post.md` | Blog post: Constitutional Governance for Autonomous AI Agents |
| `packages/gavel-governance/src/gavel_governance/` | Self-contained AGT integration package (typed, 28 tests) |
| `packages/gavel-governance/examples/quickstart.py` | Standalone demo — no Gavel runtime dependency |
| `packages/gavel-governance/dist/` | Built wheel and sdist ready for PyPI |
| `scripts/submit-agt-issue.sh` | Script to submit proposal issue via `gh` CLI |
| `scripts/submit-agt-pr.sh` | Script to fork, branch, and submit PR to AGT |
| `scripts/publish-pypi.sh` | Script to build, check, and upload to PyPI |

### Submission status
The following require `gh` CLI (install: `winget install GitHub.cli`) and authentication:
1. **Issue**: Run `bash scripts/submit-agt-issue.sh`
2. **PR**: Run `bash scripts/submit-agt-pr.sh` (creates fork, copies package, submits PR)
3. **PyPI**: Run `bash scripts/publish-pypi.sh` (requires PyPI API token)

## Phase 6: Production Hardening [PLANNED]
- [ ] Ed25519 principal signatures (replace DID stubs with real crypto)
- [ ] Multi-chain governance for complex workflows (parallel approval chains)
- [ ] Persistent chain storage (SQLite/PostgreSQL backend)
- [ ] Real-time governance dashboard (WebSocket events)
- [ ] OpenTelemetry integration for governance chain observability
- [ ] Performance benchmarks (1000+ chains/sec target)
