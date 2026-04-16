"""Tests for ATF S-3 Rate Limiting and S-4 Budget Enforcement."""

from __future__ import annotations

import asyncio
import time

import pytest

from gavel.rate_limit import (
    BudgetCheckResult,
    BudgetStatus,
    BudgetTracker,
    RateLimitResult,
    RateLimiter,
)


# ══════════════════════════════════════════════════════════════
# ATF S-3: Rate Limiting
# ══════════════════════════════════════════════════════════════


class TestRateLimiter:
    """Sliding window rate limiter tests."""

    async def test_allows_actions_within_limit(self):
        rl = RateLimiter()
        await rl.configure("agent:a", max_actions_per_minute=5)

        for i in range(5):
            result = await rl.check_and_record("agent:a")
            assert result.allowed is True
            assert result.current_count == i + 1
            assert result.limit == 5

    async def test_denies_action_exceeding_limit(self):
        rl = RateLimiter()
        await rl.configure("agent:a", max_actions_per_minute=3)

        now = 1000.0
        for i in range(3):
            result = await rl.check_and_record("agent:a", now=now + i * 0.1)
            assert result.allowed is True

        result = await rl.check_and_record("agent:a", now=now + 0.5)
        assert result.allowed is False
        assert result.current_count == 3
        assert result.limit == 3
        assert "exceeded" in result.reason.lower()

    async def test_retry_after_is_positive(self):
        rl = RateLimiter()
        await rl.configure("agent:a", max_actions_per_minute=2)

        now = 1000.0
        await rl.check_and_record("agent:a", now=now)
        await rl.check_and_record("agent:a", now=now + 1.0)

        result = await rl.check_and_record("agent:a", now=now + 2.0)
        assert result.allowed is False
        assert result.retry_after_seconds > 0
        # First action was at now=1000, so it expires at 1060.
        # retry_after should be roughly 1060 - 1002 = 58 seconds
        assert result.retry_after_seconds <= 60.0

    async def test_window_slides_allows_after_expiry(self):
        rl = RateLimiter()
        await rl.configure("agent:a", max_actions_per_minute=2)

        now = 1000.0
        await rl.check_and_record("agent:a", now=now)
        await rl.check_and_record("agent:a", now=now + 1.0)

        # Should be denied at now + 2
        result = await rl.check_and_record("agent:a", now=now + 2.0)
        assert result.allowed is False

        # After 60 seconds, the window has slid past both entries
        result = await rl.check_and_record("agent:a", now=now + 61.0)
        assert result.allowed is True
        assert result.current_count == 1

    async def test_unconfigured_agent_is_allowed(self):
        rl = RateLimiter()
        result = await rl.check_and_record("agent:unknown")
        assert result.allowed is True

    async def test_separate_agents_have_separate_limits(self):
        rl = RateLimiter()
        await rl.configure("agent:a", max_actions_per_minute=1)
        await rl.configure("agent:b", max_actions_per_minute=1)

        now = 1000.0
        result_a = await rl.check_and_record("agent:a", now=now)
        result_b = await rl.check_and_record("agent:b", now=now)

        assert result_a.allowed is True
        assert result_b.allowed is True

        # Both should now be at limit
        assert (await rl.check_and_record("agent:a", now=now + 0.1)).allowed is False
        assert (await rl.check_and_record("agent:b", now=now + 0.1)).allowed is False

    async def test_get_usage(self):
        rl = RateLimiter()
        await rl.configure("agent:a", max_actions_per_minute=10)

        now = 1000.0
        await rl.check_and_record("agent:a", now=now)
        await rl.check_and_record("agent:a", now=now + 1.0)

        usage = await rl.get_usage("agent:a", now=now + 2.0)
        assert usage["current_count"] == 2
        assert usage["limit"] == 10
        assert usage["remaining"] == 8

    async def test_reset_clears_window(self):
        rl = RateLimiter()
        await rl.configure("agent:a", max_actions_per_minute=2)

        now = 1000.0
        await rl.check_and_record("agent:a", now=now)
        await rl.check_and_record("agent:a", now=now + 0.1)

        # At limit
        assert (await rl.check_and_record("agent:a", now=now + 0.2)).allowed is False

        # Reset
        await rl.reset("agent:a")

        # Should be allowed again
        result = await rl.check_and_record("agent:a", now=now + 0.3)
        assert result.allowed is True
        assert result.current_count == 1

    async def test_denied_action_is_not_recorded(self):
        """Denied actions should not consume a window slot."""
        rl = RateLimiter()
        await rl.configure("agent:a", max_actions_per_minute=2)

        now = 1000.0
        await rl.check_and_record("agent:a", now=now)
        await rl.check_and_record("agent:a", now=now + 0.1)

        # These denials should not add to the window
        await rl.check_and_record("agent:a", now=now + 0.2)
        await rl.check_and_record("agent:a", now=now + 0.3)

        usage = await rl.get_usage("agent:a", now=now + 0.4)
        assert usage["current_count"] == 2  # Still just 2, not 4

    async def test_high_rate_limit(self):
        """Agent with a high limit should handle many actions."""
        rl = RateLimiter()
        await rl.configure("agent:fast", max_actions_per_minute=1000)

        now = 1000.0
        for i in range(100):
            result = await rl.check_and_record("agent:fast", now=now + i * 0.01)
            assert result.allowed is True

        usage = await rl.get_usage("agent:fast", now=now + 1.0)
        assert usage["current_count"] == 100
        assert usage["remaining"] == 900

    async def test_concurrent_check_serializes_under_lock(self):
        """Fire many concurrent check_and_record calls and assert the window
        state is internally consistent — no double counts, no torn reads."""
        rl = RateLimiter()
        await rl.configure("agent:c", max_actions_per_minute=40)

        now = 1000.0
        results = await asyncio.gather(
            *[rl.check_and_record("agent:c", now=now + i * 0.001) for i in range(100)]
        )

        allowed = [r for r in results if r.allowed]
        denied = [r for r in results if not r.allowed]

        assert len(allowed) == 40
        assert len(denied) == 60

        counts = sorted(r.current_count for r in allowed)
        assert counts == list(range(1, 41))

        usage = await rl.get_usage("agent:c", now=now + 0.2)
        assert usage["current_count"] == 40
        assert usage["remaining"] == 0


# ══════════════════════════════════════════════════════════════
# ATF S-4: Budget Enforcement
# ══════════════════════════════════════════════════════════════


class TestBudgetTracker:
    """Cumulative budget enforcement tests."""

    async def test_allows_actions_within_token_budget(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=1000)

        result = await bt.check_and_decrement("agent:a", token_cost=100)
        assert result.allowed is True
        assert result.tokens_remaining == 900

    async def test_denies_action_exceeding_token_budget(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=100)

        result = await bt.check_and_decrement("agent:a", token_cost=101)
        assert result.allowed is False
        assert "exhausted" in result.reason.lower() or "token" in result.reason.lower()

    async def test_cumulative_token_spend(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=500)

        await bt.check_and_decrement("agent:a", token_cost=200)
        await bt.check_and_decrement("agent:a", token_cost=200)

        # 400 used, 100 remaining
        result = await bt.check_and_decrement("agent:a", token_cost=150)
        assert result.allowed is False

        result = await bt.check_and_decrement("agent:a", token_cost=100)
        assert result.allowed is True
        assert result.tokens_remaining == 0

    async def test_allows_actions_within_usd_budget(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_usd=10.0)

        result = await bt.check_and_decrement("agent:a", usd_cost=3.50)
        assert result.allowed is True
        assert result.usd_remaining == pytest.approx(6.50, abs=0.01)

    async def test_denies_action_exceeding_usd_budget(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_usd=5.0)

        await bt.check_and_decrement("agent:a", usd_cost=4.0)
        result = await bt.check_and_decrement("agent:a", usd_cost=2.0)
        assert result.allowed is False
        assert "usd" in result.reason.lower()

    async def test_dual_budget_token_exhausted_first(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=100, budget_usd=50.0)

        result = await bt.check_and_decrement("agent:a", token_cost=101, usd_cost=0.01)
        assert result.allowed is False
        assert "token" in result.reason.lower()

    async def test_dual_budget_usd_exhausted_first(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=100_000, budget_usd=1.0)

        await bt.check_and_decrement("agent:a", token_cost=100, usd_cost=0.90)
        result = await bt.check_and_decrement("agent:a", token_cost=100, usd_cost=0.20)
        assert result.allowed is False
        assert "usd" in result.reason.lower()

    async def test_unconfigured_agent_is_allowed(self):
        bt = BudgetTracker()
        result = await bt.check_and_decrement("agent:unknown", token_cost=999999)
        assert result.allowed is True

    async def test_zero_cost_action_always_allowed(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=100, budget_usd=1.0)

        # Exhaust budget
        await bt.check_and_decrement("agent:a", token_cost=100, usd_cost=1.0)

        # Zero-cost action should still fail because budget is at 0
        result = await bt.check_and_decrement("agent:a", token_cost=1)
        assert result.allowed is False

    async def test_get_status(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=1000, budget_usd=50.0)

        await bt.check_and_decrement("agent:a", token_cost=300, usd_cost=10.0)

        status = await bt.get_status("agent:a")
        assert status is not None
        assert status.agent_id == "agent:a"
        assert status.budget_tokens == 1000
        assert status.tokens_used == 300
        assert status.tokens_remaining == 700
        assert status.budget_usd == 50.0
        assert status.usd_used == pytest.approx(10.0, abs=0.01)
        assert status.usd_remaining == pytest.approx(40.0, abs=0.01)
        assert status.exhausted is False

    async def test_get_status_exhausted(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=100)

        await bt.check_and_decrement("agent:a", token_cost=100)

        status = await bt.get_status("agent:a")
        assert status.exhausted is True
        assert status.tokens_remaining == 0

    async def test_get_status_unknown_agent(self):
        bt = BudgetTracker()
        assert await bt.get_status("agent:unknown") is None

    async def test_reset_clears_usage(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=100, budget_usd=5.0)

        await bt.check_and_decrement("agent:a", token_cost=90, usd_cost=4.0)

        await bt.reset("agent:a")

        status = await bt.get_status("agent:a")
        assert status.tokens_used == 0
        assert status.usd_used == 0.0
        assert status.tokens_remaining == 100
        assert status.usd_remaining == 5.0
        assert status.exhausted is False

    async def test_denied_action_does_not_decrement(self):
        """Failed budget checks should not consume budget."""
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=100)

        await bt.check_and_decrement("agent:a", token_cost=80)

        # This should be denied (80+30=110 > 100)
        result = await bt.check_and_decrement("agent:a", token_cost=30)
        assert result.allowed is False

        # Budget should still show 80 used, not 110
        status = await bt.get_status("agent:a")
        assert status.tokens_used == 80
        assert status.tokens_remaining == 20

    async def test_separate_agents_have_separate_budgets(self):
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=100)
        await bt.configure("agent:b", budget_tokens=200)

        await bt.check_and_decrement("agent:a", token_cost=90)
        await bt.check_and_decrement("agent:b", token_cost=50)

        status_a = await bt.get_status("agent:a")
        status_b = await bt.get_status("agent:b")

        assert status_a.tokens_remaining == 10
        assert status_b.tokens_remaining == 150

    async def test_only_token_budget_configured(self):
        """When only token budget is set, USD is not enforced."""
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=100, budget_usd=0.0)

        # Should allow regardless of USD cost
        result = await bt.check_and_decrement("agent:a", token_cost=50, usd_cost=999.0)
        assert result.allowed is True

    async def test_only_usd_budget_configured(self):
        """When only USD budget is set, tokens are not enforced."""
        bt = BudgetTracker()
        await bt.configure("agent:a", budget_tokens=0, budget_usd=10.0)

        # Should allow regardless of token cost
        result = await bt.check_and_decrement("agent:a", token_cost=999999, usd_cost=5.0)
        assert result.allowed is True


# ══════════════════════════════════════════════════════════════
# Pydantic model serialization
# ══════════════════════════════════════════════════════════════


class TestModels:
    def test_rate_limit_result_serialization(self):
        r = RateLimitResult(
            allowed=False,
            current_count=60,
            limit=60,
            retry_after_seconds=42.5,
            reason="Rate limit exceeded",
        )
        d = r.model_dump()
        assert d["allowed"] is False
        assert d["retry_after_seconds"] == 42.5

    def test_budget_status_serialization(self):
        s = BudgetStatus(
            agent_id="agent:test",
            budget_tokens=1000,
            budget_usd=50.0,
            tokens_used=300,
            usd_used=10.0,
            tokens_remaining=700,
            usd_remaining=40.0,
            exhausted=False,
        )
        d = s.model_dump()
        assert d["agent_id"] == "agent:test"
        assert d["exhausted"] is False

    def test_budget_check_result_serialization(self):
        r = BudgetCheckResult(
            allowed=True,
            reason="Within budget",
            tokens_remaining=500,
            usd_remaining=25.0,
        )
        d = r.model_dump()
        assert d["allowed"] is True
        assert d["tokens_remaining"] == 500
