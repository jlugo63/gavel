"""
Webhook Notifications — push governance events to external systems.

Enterprise deployments need to integrate governance events with existing
infrastructure: SIEM systems (Splunk, Sentinel), ticketing (Jira, ServiceNow),
alerting (PagerDuty, OpsGenie), and audit platforms.

This module provides:

  1. WebhookSubscription — registered endpoint + event filter + signing secret
  2. WebhookPayload — structured notification with HMAC signature
  3. WebhookDelivery — delivery attempt record with retry state
  4. WebhookManager — subscription management + event routing + delivery tracking

Delivery guarantees:
  - At-least-once delivery with configurable retry (default 3 attempts)
  - Exponential backoff: 1s, 4s, 16s (base ** attempt)
  - HMAC-SHA256 signature in X-Gavel-Signature header
  - Dead letter queue for exhausted retries
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Event types for filtering ─────────────────────────────────

class WebhookEventType(str, Enum):
    # Governance chain events
    CHAIN_CREATED = "chain.created"
    CHAIN_APPROVED = "chain.approved"
    CHAIN_DENIED = "chain.denied"
    CHAIN_COMPLETED = "chain.completed"
    CHAIN_ESCALATED = "chain.escalated"
    CHAIN_TIMED_OUT = "chain.timed_out"
    CHAIN_ROLLED_BACK = "chain.rolled_back"

    # Agent lifecycle
    AGENT_ENROLLED = "agent.enrolled"
    AGENT_SUSPENDED = "agent.suspended"
    AGENT_REJECTED = "agent.rejected"
    AGENT_TOKEN_REVOKED = "agent.token_revoked"

    # Incidents
    INCIDENT_CREATED = "incident.created"
    INCIDENT_CRITICAL = "incident.critical"
    INCIDENT_RESOLVED = "incident.resolved"
    INCIDENT_OVERDUE = "incident.overdue"

    # Security
    KILLSWITCH_ACTIVATED = "security.killswitch"
    COLLUSION_DETECTED = "security.collusion"
    EVASION_DETECTED = "security.evasion"
    DRIFT_DETECTED = "security.drift"

    # Compliance
    COMPLIANCE_EXPORT = "compliance.export"
    READINESS_FAILED = "compliance.readiness_failed"

    # Catch-all
    ALL = "*"


# ── Subscription model ────────────────────────────────────────

class WebhookSubscription(BaseModel):
    """A registered webhook endpoint with event filter."""
    subscription_id: str = Field(default_factory=lambda: f"wh-{uuid.uuid4().hex[:8]}")
    url: str                                  # HTTPS endpoint to POST to
    description: str = ""
    event_types: list[WebhookEventType] = Field(default_factory=lambda: [WebhookEventType.ALL])
    signing_secret: str = Field(default_factory=lambda: secrets.token_hex(32))
    org_id: str = ""                          # Tenant scope (empty = platform-wide)
    active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
    max_retries: int = 3
    headers: dict[str, str] = Field(default_factory=dict)  # Extra headers to include

    def matches_event(self, event_type: WebhookEventType) -> bool:
        """Check if this subscription should receive the given event type."""
        if not self.active:
            return False
        if WebhookEventType.ALL in self.event_types:
            return True
        return event_type in self.event_types


# ── Payload and delivery ──────────────────────────────────────

class WebhookPayload(BaseModel):
    """Structured webhook notification payload."""
    payload_id: str = Field(default_factory=lambda: f"wp-{uuid.uuid4().hex[:8]}")
    event_type: WebhookEventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: dict[str, Any] = Field(default_factory=dict)
    chain_id: str = ""
    agent_id: str = ""
    org_id: str = ""

    def to_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, default=str)

    def compute_signature(self, secret: str) -> str:
        """Compute HMAC-SHA256 signature for the payload."""
        body = self.to_json().encode()
        return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class DeliveryStatus(str, Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"
    DEAD_LETTER = "dead_letter"


class WebhookDelivery(BaseModel):
    """Record of a webhook delivery attempt."""
    delivery_id: str = Field(default_factory=lambda: f"wd-{uuid.uuid4().hex[:8]}")
    subscription_id: str
    payload_id: str
    status: DeliveryStatus = DeliveryStatus.PENDING
    attempts: int = 0
    max_retries: int = 3
    last_attempt_at: Optional[datetime] = None
    next_retry_at: Optional[datetime] = None
    last_status_code: Optional[int] = None
    last_error: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def record_attempt(self, success: bool, status_code: int | None = None, error: str = "") -> None:
        """Record a delivery attempt result."""
        self.attempts += 1
        self.last_attempt_at = datetime.now(timezone.utc)
        self.last_status_code = status_code
        self.last_error = error

        if success:
            self.status = DeliveryStatus.DELIVERED
            self.next_retry_at = None
        elif self.attempts >= self.max_retries:
            self.status = DeliveryStatus.DEAD_LETTER
            self.next_retry_at = None
        else:
            self.status = DeliveryStatus.RETRYING
            backoff = 4 ** self.attempts  # 4s, 16s, 64s...
            self.next_retry_at = datetime.now(timezone.utc) + timedelta(seconds=backoff)

    @property
    def is_terminal(self) -> bool:
        return self.status in (DeliveryStatus.DELIVERED, DeliveryStatus.DEAD_LETTER)


# ── Webhook Manager ───────────────────────────────────────────

class WebhookManager:
    """Manages webhook subscriptions, event routing, and delivery tracking."""

    def __init__(self):
        self._subscriptions: dict[str, WebhookSubscription] = {}
        self._deliveries: dict[str, WebhookDelivery] = {}  # delivery_id -> delivery
        self._dead_letters: list[WebhookDelivery] = []

    # ── Subscription management ───────────────────────────────

    def register(
        self,
        url: str,
        event_types: list[WebhookEventType] | None = None,
        description: str = "",
        org_id: str = "",
        headers: dict[str, str] | None = None,
        max_retries: int = 3,
    ) -> WebhookSubscription:
        """Register a new webhook subscription."""
        sub = WebhookSubscription(
            url=url,
            event_types=event_types or [WebhookEventType.ALL],
            description=description,
            org_id=org_id,
            headers=headers or {},
            max_retries=max_retries,
        )
        self._subscriptions[sub.subscription_id] = sub
        return sub

    def unregister(self, subscription_id: str) -> bool:
        return self._subscriptions.pop(subscription_id, None) is not None

    def get_subscription(self, subscription_id: str) -> WebhookSubscription | None:
        return self._subscriptions.get(subscription_id)

    def list_subscriptions(self, org_id: str | None = None) -> list[WebhookSubscription]:
        subs = list(self._subscriptions.values())
        if org_id is not None:
            subs = [s for s in subs if s.org_id == org_id or s.org_id == ""]
        return subs

    def disable(self, subscription_id: str) -> bool:
        sub = self._subscriptions.get(subscription_id)
        if sub:
            sub.active = False
            return True
        return False

    def enable(self, subscription_id: str) -> bool:
        sub = self._subscriptions.get(subscription_id)
        if sub:
            sub.active = True
            return True
        return False

    # ── Event dispatch ────────────────────────────────────────

    def dispatch(self, payload: WebhookPayload) -> list[WebhookDelivery]:
        """Route an event to all matching subscriptions, creating delivery records.

        Returns delivery records for all matching subscriptions. The actual
        HTTP delivery is the caller's responsibility — this module creates
        the delivery records with signatures and tracks state.
        """
        deliveries = []
        for sub in self._subscriptions.values():
            if not sub.matches_event(payload.event_type):
                continue
            if sub.org_id and payload.org_id and sub.org_id != payload.org_id:
                continue

            delivery = WebhookDelivery(
                subscription_id=sub.subscription_id,
                payload_id=payload.payload_id,
                max_retries=sub.max_retries,
            )
            self._deliveries[delivery.delivery_id] = delivery
            deliveries.append(delivery)

        return deliveries

    def prepare_request(self, delivery: WebhookDelivery, payload: WebhookPayload) -> dict[str, Any] | None:
        """Prepare the HTTP request details for a delivery.

        Returns a dict with url, headers, body — ready for the caller
        to send via httpx/aiohttp/requests.
        """
        sub = self._subscriptions.get(delivery.subscription_id)
        if not sub:
            return None

        body = payload.to_json()
        signature = payload.compute_signature(sub.signing_secret)

        headers = {
            "Content-Type": "application/json",
            "X-Gavel-Signature": f"sha256={signature}",
            "X-Gavel-Event": payload.event_type.value,
            "X-Gavel-Delivery": delivery.delivery_id,
        }
        headers.update(sub.headers)

        return {
            "url": sub.url,
            "headers": headers,
            "body": body,
        }

    def record_delivery_result(
        self,
        delivery_id: str,
        success: bool,
        status_code: int | None = None,
        error: str = "",
    ) -> WebhookDelivery | None:
        """Record the result of a delivery attempt."""
        delivery = self._deliveries.get(delivery_id)
        if not delivery:
            return None
        delivery.record_attempt(success, status_code, error)
        if delivery.status == DeliveryStatus.DEAD_LETTER:
            self._dead_letters.append(delivery)
        return delivery

    # ── Query ─────────────────────────────────────────────────

    def get_delivery(self, delivery_id: str) -> WebhookDelivery | None:
        return self._deliveries.get(delivery_id)

    def pending_deliveries(self) -> list[WebhookDelivery]:
        """Get deliveries that need to be sent or retried."""
        now = datetime.now(timezone.utc)
        return [
            d for d in self._deliveries.values()
            if d.status in (DeliveryStatus.PENDING, DeliveryStatus.RETRYING)
            and (d.next_retry_at is None or now >= d.next_retry_at)
        ]

    def dead_letters(self) -> list[WebhookDelivery]:
        return list(self._dead_letters)

    @property
    def subscription_count(self) -> int:
        return len(self._subscriptions)

    @property
    def delivery_count(self) -> int:
        return len(self._deliveries)
