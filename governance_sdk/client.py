"""
Governance SDK — Client
Thin synchronous wrapper over the Gavel governance gateway.
"""

from __future__ import annotations

from typing import Any, Union

import httpx

from governance_sdk.models import ApprovalResult, ProposalResult


class GovernanceClient:
    """
    Client for the Gavel governance gateway.

    Submits proposals for policy evaluation, retrieves decisions,
    and optionally approves escalated proposals with a human API key.
    """

    def __init__(
        self,
        gateway_url: str,
        actor_id: str,
        api_key: str | None = None,
        timeout: float = 10.0,
    ):
        """
        Args:
            gateway_url: Base URL of the gateway (e.g. "http://localhost:8000")
            actor_id: Identity for audit logging (e.g. "agent:openclaw")
            api_key: Bearer token for /approve (only needed for human approval)
            timeout: HTTP request timeout in seconds
        """
        self.gateway_url = gateway_url.rstrip("/")
        self.actor_id = actor_id
        self.api_key = api_key
        self._client = httpx.Client(timeout=timeout)

    def propose(
        self,
        action_type: str,
        content: Union[str, dict[str, Any]],
    ) -> ProposalResult:
        """
        Submit a proposed action to the governance gateway.

        Args:
            action_type: Category of action (e.g. "bash", "file_write")
            content: The command or payload to evaluate

        Returns:
            ProposalResult with decision, event IDs, and risk score.
        """
        resp = self._client.post(
            f"{self.gateway_url}/propose",
            json={
                "actor_id": self.actor_id,
                "action_type": action_type,
                "content": content,
            },
        )

        body = resp.json()

        return ProposalResult(
            decision=body.get("decision", "UNKNOWN"),
            intent_event_id=body.get("intent_event_id", ""),
            policy_event_id=body.get("policy_event_id", ""),
            risk_score=body.get("risk_score"),
            violations=body.get("violations", []),
            raw=body,
        )

    def approve(
        self,
        intent_event_id: str,
        policy_event_id: str,
    ) -> ApprovalResult:
        """
        Approve an escalated proposal via POST /approve.

        Requires api_key to be set on the client.

        Args:
            intent_event_id: UUID of the INBOUND_INTENT event
            policy_event_id: UUID of the POLICY_EVAL event

        Returns:
            ApprovalResult with success status and approval event ID.
        """
        if not self.api_key:
            return ApprovalResult(
                success=False,
                raw={"error": "No api_key configured on client."},
            )

        resp = self._client.post(
            f"{self.gateway_url}/approve",
            json={
                "intent_event_id": intent_event_id,
                "policy_event_id": policy_event_id,
            },
            headers={"Authorization": f"Bearer {self.api_key}"},
        )

        body = resp.json()

        return ApprovalResult(
            success=resp.status_code == 200,
            event_id=body.get("approval_event_id"),
            raw=body,
        )

    def health(self) -> dict:
        """Check gateway health via GET /health."""
        resp = self._client.get(f"{self.gateway_url}/health")
        return resp.json()
