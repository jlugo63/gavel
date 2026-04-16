"""
Cross-chain collusion detection — Phase 7.

Separation of powers (gavel/separation.py) enforces that proposer ≠
reviewer ≠ approver on a *single* chain. That's necessary but not
sufficient. A group of agents can still collude across many chains by
rotating roles: A proposes while B approves, then B proposes while A
approves. On any single chain the separation rule is satisfied, but
over time the pair has effectively reviewed each other exclusively.

This module detects that pattern.

Signals:

  1. Mutual approval loops — agent pairs that repeatedly approve each
     other's proposals.
  2. Closed review cliques — a small set of agents (k ≤ 4) that
     exclusively review each other.
  3. Proposer→approver pipelines with no other reviewers — persistent
     1:1 relationships.
  4. Round-robin patterns — agents that cycle roles in a fixed order
     over many chains.

Every signal returns a CollusionFinding with:
  - the implicated agent set
  - number of supporting chains
  - a clique score (how closed the group is)
  - suggested action

This is deterministic: we compute graph-level statistics on the
observed role graph without any statistical models.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CollusionSignal(str, Enum):
    MUTUAL_APPROVAL = "mutual_approval"
    CLOSED_CLIQUE = "closed_clique"
    ONE_TO_ONE_PIPELINE = "one_to_one_pipeline"
    ROUND_ROBIN = "round_robin"


class CollusionSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ChainParticipation(BaseModel):
    """One observed governance chain with its role assignments."""

    chain_id: str
    proposer: str
    reviewers: list[str] = Field(default_factory=list)
    approver: Optional[str] = None
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CollusionFinding(BaseModel):
    """One detected collusion pattern."""

    signal: CollusionSignal
    severity: CollusionSeverity
    implicated: list[str]
    supporting_chains: list[str] = Field(default_factory=list)
    clique_score: float = 0.0  # 0..1; higher = more closed
    detail: str = ""
    suggested_action: str = ""


# ── Detector ───────────────────────────────────────────────────

_MIN_CHAINS_FOR_MUTUAL = 4            # min mutual-approval count
_MIN_CHAINS_FOR_PIPELINE = 6          # min 1:1 pipeline count
_CLOSED_CLIQUE_MIN_SIZE = 3
_CLOSED_CLIQUE_MAX_SIZE = 4
_CLOSED_CLIQUE_DENSITY = 0.75         # fraction of reviews staying inside the clique
_CLOSED_CLIQUE_MIN_CHAINS = 8
_ROUND_ROBIN_MIN_CHAINS = 6


class CollusionDetector:
    """Accumulate chain participations and scan for cross-chain collusion."""

    def __init__(self, window: int = 1000):
        self._window = window
        self._chains: deque[ChainParticipation] = deque(maxlen=window)
        # Index for O(1) mutual approval lookups: (proposer, approver) -> [chain_id, ...]
        self._approval_index: dict[tuple[str, str], list[str]] = defaultdict(list)

    def observe(self, participation: ChainParticipation) -> None:
        # If the deque is full, the leftmost item will be evicted automatically.
        # Remove evicted entry from the approval index.
        if len(self._chains) == self._chains.maxlen:
            evicted = self._chains[0]
            if evicted.approver and evicted.proposer != evicted.approver:
                key = (evicted.proposer, evicted.approver)
                idx_list = self._approval_index.get(key)
                if idx_list:
                    try:
                        idx_list.remove(evicted.chain_id)
                    except ValueError:
                        pass
                    if not idx_list:
                        self._approval_index.pop(key, None)

        self._chains.append(participation)

        # Update the approval index for the new entry
        if participation.approver and participation.proposer != participation.approver:
            self._approval_index[(participation.proposer, participation.approver)].append(
                participation.chain_id
            )

    # ---- detectors ----

    def scan(self) -> list[CollusionFinding]:
        findings: list[CollusionFinding] = []
        findings += self._detect_mutual_approval()
        findings += self._detect_one_to_one_pipeline()
        findings += self._detect_closed_cliques()
        findings += self._detect_round_robin()
        return findings

    def _detect_mutual_approval(self) -> list[CollusionFinding]:
        """Pair (A, B) where A approves B ≥ k times AND B approves A ≥ k times."""
        # Use the pre-built approval index instead of scanning all chains
        approvals = self._approval_index

        findings: list[CollusionFinding] = []
        seen: set[frozenset[str]] = set()
        for (proposer, approver), chain_ids in approvals.items():
            if len(chain_ids) < _MIN_CHAINS_FOR_MUTUAL:
                continue
            reverse = approvals.get((approver, proposer), [])
            if len(reverse) < _MIN_CHAINS_FOR_MUTUAL:
                continue
            pair = frozenset([proposer, approver])
            if pair in seen:
                continue
            seen.add(pair)
            supporting = sorted(set(chain_ids) | set(reverse))
            total = len(supporting)
            findings.append(
                CollusionFinding(
                    signal=CollusionSignal.MUTUAL_APPROVAL,
                    severity=CollusionSeverity.HIGH,
                    implicated=sorted(pair),
                    supporting_chains=supporting,
                    clique_score=1.0,
                    detail=(
                        f"{proposer} and {approver} approved each other {len(chain_ids)} "
                        f"and {len(reverse)} times across {total} chains"
                    ),
                    suggested_action=(
                        "Force rotation of reviewers; suspend autonomy promotion for "
                        "both agents pending human review"
                    ),
                )
            )
        return findings

    def _detect_one_to_one_pipeline(self) -> list[CollusionFinding]:
        """Proposer who is *only* ever approved by one other agent."""
        proposer_to_approvers: dict[str, Counter] = defaultdict(Counter)
        proposer_chains: dict[str, list[str]] = defaultdict(list)
        for p in self._chains:
            if p.approver and p.approver != p.proposer:
                proposer_to_approvers[p.proposer][p.approver] += 1
                proposer_chains[p.proposer].append(p.chain_id)

        findings: list[CollusionFinding] = []
        for proposer, approvers in proposer_to_approvers.items():
            total = sum(approvers.values())
            if total < _MIN_CHAINS_FOR_PIPELINE:
                continue
            if len(approvers) != 1:
                continue
            sole_approver = next(iter(approvers))
            findings.append(
                CollusionFinding(
                    signal=CollusionSignal.ONE_TO_ONE_PIPELINE,
                    severity=CollusionSeverity.MEDIUM,
                    implicated=sorted([proposer, sole_approver]),
                    supporting_chains=proposer_chains[proposer],
                    clique_score=1.0,
                    detail=(
                        f"{proposer}'s {total} chains were all approved by "
                        f"{sole_approver}"
                    ),
                    suggested_action="Require ≥2 distinct approvers for this proposer",
                )
            )
        return findings

    def _detect_closed_cliques(self) -> list[CollusionFinding]:
        """Groups of 3-4 agents whose reviews stay mostly inside the group."""
        # Build an undirected review edge multiset.
        # Edge = pair (reviewer, proposer) — a reviewer reviewed a proposer.
        edges: Counter[frozenset[str]] = Counter()
        all_edges_by_agent: dict[str, Counter[str]] = defaultdict(Counter)
        chain_edges: dict[frozenset[str], list[str]] = defaultdict(list)

        for p in self._chains:
            reviewers = list(p.reviewers)
            if p.approver:
                reviewers.append(p.approver)
            for reviewer in reviewers:
                if reviewer == p.proposer:
                    continue
                edge = frozenset([p.proposer, reviewer])
                if len(edge) != 2:
                    continue
                edges[edge] += 1
                all_edges_by_agent[p.proposer][reviewer] += 1
                all_edges_by_agent[reviewer][p.proposer] += 1
                chain_edges[edge].append(p.chain_id)

        if not edges:
            return []

        # Find connected components of agents whose links are dense.
        # For every agent, rank its neighbors by edge weight and take
        # the top-k as candidate clique members.
        agents = list(all_edges_by_agent)
        findings: list[CollusionFinding] = []
        seen: set[frozenset[str]] = set()

        for agent in agents:
            neighbors = [n for n, _ in all_edges_by_agent[agent].most_common(
                _CLOSED_CLIQUE_MAX_SIZE - 1
            )]
            for size in range(_CLOSED_CLIQUE_MIN_SIZE, _CLOSED_CLIQUE_MAX_SIZE + 1):
                if len(neighbors) + 1 < size:
                    continue
                candidate = frozenset([agent] + neighbors[: size - 1])
                if candidate in seen:
                    continue
                seen.add(candidate)

                inside = 0
                outside = 0
                chain_ids: set[str] = set()
                for a in candidate:
                    for partner, cnt in all_edges_by_agent[a].items():
                        if partner in candidate:
                            inside += cnt
                            edge_key = frozenset([a, partner])
                            chain_ids.update(chain_edges.get(edge_key, []))
                        else:
                            outside += cnt
                total = inside + outside
                if total == 0:
                    continue
                density = inside / total
                if density < _CLOSED_CLIQUE_DENSITY:
                    continue
                if inside < _CLOSED_CLIQUE_MIN_CHAINS:
                    continue

                findings.append(
                    CollusionFinding(
                        signal=CollusionSignal.CLOSED_CLIQUE,
                        severity=CollusionSeverity.HIGH,
                        implicated=sorted(candidate),
                        supporting_chains=sorted(chain_ids),
                        clique_score=round(density, 3),
                        detail=(
                            f"{len(candidate)}-agent clique reviewed each other "
                            f"{inside} times ({density:.0%} closed)"
                        ),
                        suggested_action=(
                            "Require at least one reviewer outside the clique "
                            "on every chain involving these agents"
                        ),
                    )
                )
        return findings

    def _detect_round_robin(self) -> list[CollusionFinding]:
        """Fixed cyclic rotation of proposer→approver relationships.

        If we see (A→B, B→C, C→A, A→B, B→C, C→A, ...) repeating, that's a
        pre-agreed rotation masquerading as diversity.
        """
        if len(self._chains) < _ROUND_ROBIN_MIN_CHAINS:
            return []

        # Look for any cycle of length 3 or 4 among (proposer, approver)
        # pairs whose total support dominates the recent history.
        # Use list() since deque does not support slicing.
        recent_chains = list(self._chains)[-50:]
        recent_pairs = [
            (p.proposer, p.approver)
            for p in recent_chains
            if p.approver and p.proposer != p.approver
        ]
        if len(recent_pairs) < _ROUND_ROBIN_MIN_CHAINS:
            return []

        findings: list[CollusionFinding] = []
        for cycle_len in (3, 4):
            # Try to find a repeating cycle of this length.
            for start in range(len(recent_pairs) - cycle_len):
                head = tuple(recent_pairs[start : start + cycle_len])
                agents_in_head = set()
                for a, b in head:
                    agents_in_head.add(a)
                    agents_in_head.add(b)
                if len(agents_in_head) != cycle_len:
                    continue  # not a clean rotation of k distinct agents
                # Count how many consecutive repeats follow
                repeats = 1
                i = start + cycle_len
                while i + cycle_len <= len(recent_pairs):
                    if tuple(recent_pairs[i : i + cycle_len]) == head:
                        repeats += 1
                        i += cycle_len
                    else:
                        break
                if repeats >= 2:  # observed pattern twice = deliberate
                    findings.append(
                        CollusionFinding(
                            signal=CollusionSignal.ROUND_ROBIN,
                            severity=CollusionSeverity.MEDIUM,
                            implicated=sorted(agents_in_head),
                            supporting_chains=[
                                p.chain_id
                                for p in recent_chains
                                if p.proposer in agents_in_head
                                and p.approver in agents_in_head
                            ],
                            clique_score=round(1.0, 3),
                            detail=(
                                f"Observed cycle of length {cycle_len} repeating "
                                f"{repeats} times: {' → '.join(f'{a}→{b}' for a, b in head)}"
                            ),
                            suggested_action=(
                                "Force reviewer assignment randomization for this agent set"
                            ),
                        )
                    )
                    return findings  # one finding per scan is enough
        return findings
