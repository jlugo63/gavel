"""Tests for memory-leak prevention: GC, deque, lock, and cleanup methods."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from datetime import datetime, timedelta, timezone

import pytest

from gavel.chain import ChainStatus, GovernanceChain
from gavel.collusion import ChainParticipation, CollusionDetector
from gavel.enrollment import TokenManager
from gavel.events import DashboardEvent, EventBus
from gavel.rate_limit import InProcessRateLimiter, RateLimiter


# ── Fix 1: Gateway chain garbage collection ─────────────────────


class TestCleanupStaleChains:
    async def _populate(self):
        """Persist chains + related artefacts via the process-wide repos."""
        import gavel.db.engine as db_engine
        from gavel.db.repositories import (
            ChainRepository,
            EvidenceRepository,
            ExecutionTokenRepository,
            ReviewRepository,
        )
        from gavel.blastbox import EvidencePacket
        from gavel.evidence import ReviewResult

        sm = db_engine.get_sessionmaker()
        chain_repo = ChainRepository(sm)
        evidence_repo = EvidenceRepository(sm)
        review_repo = ReviewRepository(sm)
        execution_token_repo = ExecutionTokenRepository(sm)

        old_time = datetime.now(timezone.utc) - timedelta(hours=2)
        recent_time = datetime.now(timezone.utc) - timedelta(minutes=5)

        # Chain 1: completed 2 hours ago — should be GC'd
        c1 = GovernanceChain("stale-completed")
        c1.status = ChainStatus.COMPLETED
        c1.created_at = old_time
        await chain_repo.save(c1)
        await evidence_repo.save("stale-completed", EvidencePacket(chain_id="stale-completed"))
        await review_repo.save("stale-completed", ReviewResult())
        await execution_token_repo.save(
            "tok-stale",
            {
                "token_id": "tok-stale",
                "chain_id": "stale-completed",
                "agent_id": "agent:a",
                "expires_at": (old_time + timedelta(hours=1)).isoformat(),
                "used": False,
            },
        )

        # Chain 2: denied 2 hours ago — should be GC'd
        c2 = GovernanceChain("stale-denied")
        c2.status = ChainStatus.DENIED
        c2.created_at = old_time
        await chain_repo.save(c2)

        # Chain 3: completed recently — should NOT be GC'd
        c3 = GovernanceChain("recent-completed")
        c3.status = ChainStatus.COMPLETED
        c3.created_at = recent_time
        await chain_repo.save(c3)

        # Chain 4: still pending — should NOT be GC'd
        c4 = GovernanceChain("still-pending")
        c4.status = ChainStatus.PENDING
        c4.created_at = old_time
        await chain_repo.save(c4)

        return chain_repo, evidence_repo, review_repo, execution_token_repo

    async def test_removes_stale_terminal_chains(self):
        from gavel.gateway import cleanup_stale_chains
        chain_repo, evidence_repo, review_repo, execution_token_repo = await self._populate()

        removed = await cleanup_stale_chains(ttl_seconds=3600)
        assert removed == 2
        assert await chain_repo.get("stale-completed") is None
        assert await chain_repo.get("stale-denied") is None
        assert await evidence_repo.get("stale-completed") is None
        assert await execution_token_repo.get("tok-stale") is None

    async def test_keeps_recent_and_active_chains(self):
        from gavel.gateway import cleanup_stale_chains
        chain_repo, _, _, _ = await self._populate()
        await cleanup_stale_chains(ttl_seconds=3600)
        assert await chain_repo.get("recent-completed") is not None
        assert await chain_repo.get("still-pending") is not None

    async def test_custom_ttl(self):
        from gavel.gateway import cleanup_stale_chains
        await self._populate()
        # TTL of 1 second — every terminal chain should be removed.
        removed = await cleanup_stale_chains(ttl_seconds=1)
        assert removed == 3  # stale-completed, stale-denied, recent-completed

    async def test_no_chains_returns_zero(self):
        from gavel.gateway import cleanup_stale_chains
        assert await cleanup_stale_chains() == 0


# ── Fix 2: Collusion deque ──────────────────────────────────────


class TestCollusionDeque:
    def test_chains_is_deque(self):
        det = CollusionDetector(window=5)
        assert isinstance(det._chains, deque)
        assert det._chains.maxlen == 5

    def test_auto_eviction(self):
        det = CollusionDetector(window=3)
        for i in range(5):
            det.observe(ChainParticipation(
                chain_id=f"c-{i}", proposer="A", approver="B",
            ))
        assert len(det._chains) == 3
        # Only the last 3 should remain
        assert [p.chain_id for p in det._chains] == ["c-2", "c-3", "c-4"]

    def test_approval_index_maintained_on_eviction(self):
        det = CollusionDetector(window=3)
        # Fill deque so first entries get evicted
        det.observe(ChainParticipation(chain_id="c-0", proposer="X", approver="Y"))
        det.observe(ChainParticipation(chain_id="c-1", proposer="X", approver="Y"))
        det.observe(ChainParticipation(chain_id="c-2", proposer="X", approver="Y"))
        # c-0 should be in index
        assert "c-0" in det._approval_index[("X", "Y")]
        # Adding one more evicts c-0
        det.observe(ChainParticipation(chain_id="c-3", proposer="A", approver="B"))
        assert "c-0" not in det._approval_index.get(("X", "Y"), [])

    def test_mutual_approval_still_works(self):
        det = CollusionDetector(window=100)
        for i in range(4):
            det.observe(ChainParticipation(chain_id=f"ab-{i}", proposer="A", approver="B"))
        for i in range(4):
            det.observe(ChainParticipation(chain_id=f"ba-{i}", proposer="B", approver="A"))
        findings = det.scan()
        mutual = [f for f in findings if f.signal.value == "mutual_approval"]
        assert len(mutual) == 1


# ── Fix 3: EventBus thread safety ───────────────────────────────


class TestEventBusLock:
    def test_has_lock(self):
        bus = EventBus()
        assert hasattr(bus, "_lock")
        assert isinstance(bus._lock, asyncio.Lock)

    @pytest.mark.asyncio
    async def test_publish_under_lock(self):
        bus = EventBus()
        events_received = []

        async def consumer():
            async for event in bus.subscribe():
                events_received.append(event)
                if len(events_received) >= 2:
                    break

        task = asyncio.create_task(consumer())
        await asyncio.sleep(0.01)

        await bus.publish(DashboardEvent(event_type="test1"))
        await bus.publish(DashboardEvent(event_type="test2"))

        await asyncio.wait_for(task, timeout=1.0)
        assert len(events_received) == 2

    @pytest.mark.asyncio
    async def test_subscribe_unsubscribe_under_lock(self):
        bus = EventBus()
        assert bus.subscriber_count == 0

        gen = bus.subscribe()
        # Advance to the first yield point to trigger subscription
        task = asyncio.create_task(gen.__anext__())
        await asyncio.sleep(0.01)
        assert bus.subscriber_count == 1

        # Publish to unblock and then close
        await bus.publish(DashboardEvent(event_type="done"))
        await task
        await gen.aclose()
        await asyncio.sleep(0.01)
        assert bus.subscriber_count == 0


# ── Fix 4a: RateLimiter cleanup ─────────────────────────────────


class TestRateLimiterCleanup:
    async def test_last_seen_tracked(self):
        rl = InProcessRateLimiter()
        await rl.configure("agent-1", 10)
        now = 1000.0
        await rl.check_and_record("agent-1", now=now)
        assert rl._last_seen["agent-1"] == now

    async def test_cleanup_removes_stale_agents(self):
        rl = InProcessRateLimiter()
        await rl.configure("old-agent", 10)
        await rl.configure("new-agent", 10)

        old_time = 1000.0
        new_time = 90000.0  # 89000 seconds later

        await rl.check_and_record("old-agent", now=old_time)
        await rl.check_and_record("new-agent", now=new_time)

        removed = await rl.cleanup_inactive(max_age_seconds=86400, now=new_time)
        assert removed == 1
        assert "old-agent" not in rl._windows
        assert "old-agent" not in rl._limits
        assert "old-agent" not in rl._last_seen
        # new-agent should still be there
        assert "new-agent" in rl._windows

    async def test_cleanup_no_stale(self):
        rl = InProcessRateLimiter()
        await rl.configure("active", 10)
        now = 1000.0
        await rl.check_and_record("active", now=now)
        removed = await rl.cleanup_inactive(max_age_seconds=86400, now=now + 100)
        assert removed == 0


# ── Fix 4b: TokenManager cleanup ────────────────────────────────


class TestTokenManagerCleanup:
    async def test_cleanup_removes_expired_tokens(self):
        from conftest import _make_token_manager
        tm = _make_token_manager()
        # Issue a token with very short TTL
        tok = await tm.issue("agent-1", ttl_seconds=1)
        assert await tm._repo.get(tok.token) is not None

        # Manually expire it by writing back an earlier expires_at.
        tok.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        await tm._repo.save(tok)

        removed = await tm.cleanup_expired()
        assert removed == 1
        assert await tm._repo.get(tok.token) is None
        assert await tm._repo.get_by_agent(tok.agent_did) == []

    async def test_cleanup_removes_revoked_tokens(self):
        from conftest import _make_token_manager
        tm = _make_token_manager()
        tok = await tm.issue("agent-2", ttl_seconds=3600)
        await tm.revoke(tok.agent_did)

        removed = await tm.cleanup_expired()
        assert removed == 1
        assert await tm._repo.get(tok.token) is None

    async def test_cleanup_keeps_valid_tokens(self):
        from conftest import _make_token_manager
        tm = _make_token_manager()
        tok = await tm.issue("agent-3", ttl_seconds=3600)

        removed = await tm.cleanup_expired()
        assert removed == 0
        assert await tm._repo.get(tok.token) is not None
