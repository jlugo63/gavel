"""Tests for gavel.webhooks — governance event webhook notifications."""

from __future__ import annotations

import pytest

from gavel.webhooks import (
    DeliveryStatus,
    WebhookDelivery,
    WebhookEventType,
    WebhookManager,
    WebhookPayload,
    WebhookSubscription,
)


def _payload(event_type=WebhookEventType.INCIDENT_CREATED, **kwargs):
    return WebhookPayload(event_type=event_type, data={"test": True}, **kwargs)


class TestWebhookSubscription:
    def test_matches_subscribed_event(self):
        sub = WebhookSubscription(
            url="https://example.test/hook",
            event_types=[WebhookEventType.INCIDENT_CREATED],
        )
        assert sub.matches_event(WebhookEventType.INCIDENT_CREATED)
        assert not sub.matches_event(WebhookEventType.CHAIN_APPROVED)

    def test_wildcard_matches_all(self):
        sub = WebhookSubscription(
            url="https://example.test/hook",
            event_types=[WebhookEventType.ALL],
        )
        assert sub.matches_event(WebhookEventType.CHAIN_APPROVED)
        assert sub.matches_event(WebhookEventType.INCIDENT_CRITICAL)

    def test_inactive_sub_matches_nothing(self):
        sub = WebhookSubscription(
            url="https://example.test/hook",
            event_types=[WebhookEventType.ALL],
            active=False,
        )
        assert not sub.matches_event(WebhookEventType.CHAIN_APPROVED)

    def test_signing_secret_generated(self):
        sub = WebhookSubscription(url="https://example.test/hook")
        assert len(sub.signing_secret) == 64  # hex(32 bytes)


class TestWebhookPayload:
    def test_to_json(self):
        payload = _payload()
        body = payload.to_json()
        assert '"test": true' in body or '"test":true' in body

    def test_compute_signature(self):
        payload = _payload()
        sig = payload.compute_signature("secret123")
        assert len(sig) == 64  # SHA-256 hex

    def test_signature_changes_with_secret(self):
        payload = _payload()
        s1 = payload.compute_signature("secret1")
        s2 = payload.compute_signature("secret2")
        assert s1 != s2

    def test_signature_changes_with_data(self):
        p1 = WebhookPayload(event_type=WebhookEventType.CHAIN_APPROVED, data={"a": 1})
        p2 = WebhookPayload(event_type=WebhookEventType.CHAIN_APPROVED, data={"a": 2})
        assert p1.compute_signature("s") != p2.compute_signature("s")


class TestWebhookManager:
    def test_register_and_list(self):
        mgr = WebhookManager()
        sub = mgr.register("https://example.test/hook")
        assert mgr.subscription_count == 1
        assert mgr.get_subscription(sub.subscription_id) is not None

    def test_unregister(self):
        mgr = WebhookManager()
        sub = mgr.register("https://example.test/hook")
        assert mgr.unregister(sub.subscription_id)
        assert mgr.subscription_count == 0

    def test_disable_and_enable(self):
        mgr = WebhookManager()
        sub = mgr.register("https://example.test/hook")
        mgr.disable(sub.subscription_id)
        assert not mgr.get_subscription(sub.subscription_id).active
        mgr.enable(sub.subscription_id)
        assert mgr.get_subscription(sub.subscription_id).active

    def test_dispatch_to_matching_sub(self):
        mgr = WebhookManager()
        mgr.register(
            "https://example.test/hook",
            event_types=[WebhookEventType.INCIDENT_CREATED],
        )
        deliveries = mgr.dispatch(_payload(WebhookEventType.INCIDENT_CREATED))
        assert len(deliveries) == 1

    def test_dispatch_skips_non_matching(self):
        mgr = WebhookManager()
        mgr.register(
            "https://example.test/hook",
            event_types=[WebhookEventType.INCIDENT_CREATED],
        )
        deliveries = mgr.dispatch(_payload(WebhookEventType.CHAIN_APPROVED))
        assert len(deliveries) == 0

    def test_dispatch_fan_out(self):
        mgr = WebhookManager()
        mgr.register("https://a.test/hook")
        mgr.register("https://b.test/hook")
        deliveries = mgr.dispatch(_payload())
        assert len(deliveries) == 2

    def test_dispatch_respects_org_scope(self):
        mgr = WebhookManager()
        mgr.register("https://a.test/hook", org_id="org-1")
        mgr.register("https://b.test/hook", org_id="org-2")
        deliveries = mgr.dispatch(_payload(org_id="org-1"))
        assert len(deliveries) == 1

    def test_prepare_request(self):
        mgr = WebhookManager()
        sub = mgr.register("https://example.test/hook")
        payload = _payload()
        deliveries = mgr.dispatch(payload)
        req = mgr.prepare_request(deliveries[0], payload)
        assert req is not None
        assert req["url"] == "https://example.test/hook"
        assert "X-Gavel-Signature" in req["headers"]
        assert req["headers"]["X-Gavel-Signature"].startswith("sha256=")

    def test_record_success(self):
        mgr = WebhookManager()
        mgr.register("https://example.test/hook")
        deliveries = mgr.dispatch(_payload())
        mgr.record_delivery_result(deliveries[0].delivery_id, success=True, status_code=200)
        d = mgr.get_delivery(deliveries[0].delivery_id)
        assert d.status == DeliveryStatus.DELIVERED

    def test_record_failure_retrying(self):
        mgr = WebhookManager()
        mgr.register("https://example.test/hook", max_retries=3)
        deliveries = mgr.dispatch(_payload())
        mgr.record_delivery_result(deliveries[0].delivery_id, success=False, status_code=500, error="server error")
        d = mgr.get_delivery(deliveries[0].delivery_id)
        assert d.status == DeliveryStatus.RETRYING
        assert d.attempts == 1

    def test_exhausted_retries_dead_letter(self):
        mgr = WebhookManager()
        mgr.register("https://example.test/hook", max_retries=2)
        deliveries = mgr.dispatch(_payload())
        did = deliveries[0].delivery_id
        mgr.record_delivery_result(did, success=False, error="fail 1")
        mgr.record_delivery_result(did, success=False, error="fail 2")
        d = mgr.get_delivery(did)
        assert d.status == DeliveryStatus.DEAD_LETTER
        assert len(mgr.dead_letters()) == 1

    def test_pending_deliveries(self):
        mgr = WebhookManager()
        mgr.register("https://example.test/hook")
        mgr.dispatch(_payload())
        pending = mgr.pending_deliveries()
        assert len(pending) == 1

    def test_list_subscriptions_by_org(self):
        mgr = WebhookManager()
        mgr.register("https://a.test", org_id="org-1")
        mgr.register("https://b.test", org_id="org-2")
        mgr.register("https://c.test")  # platform-wide
        subs = mgr.list_subscriptions(org_id="org-1")
        assert len(subs) == 2  # org-1 + platform-wide
