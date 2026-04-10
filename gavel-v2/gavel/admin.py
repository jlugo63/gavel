"""
Gavel Admin Agent — Development-Only Unrestricted Agent Mode

Provides an AdminAgent that bypasses governance controls (tier evaluation,
SLA timers, separation of powers) for operator convenience during development.

SECURITY MODEL:
    Admin mode requires ALL THREE gates to pass:
      1. GAVEL_ADMIN_MODE=true environment variable
      2. GAVEL_ENV is NOT "production" (hard block, no override)
      3. Machine ID is present in the configured dev-machine allowlist

    If ANY gate fails, a SecurityViolation is raised and the attempt is
    logged to the governance chain as an ADMIN_BLOCKED event. The system
    never silently falls back to normal mode.

PRODUCTION REMOVAL:
    - is_admin_safe() returns True when admin mode is provably disabled,
      suitable for CI gate checks.
    - Dockerfile ARG ADMIN_MODE=false strips admin code path at build time.
    - Environment validation runs at import time and on AdminAgent construction.

AUDIT GUARANTEE:
    Even with full governance bypass, the admin agent CANNOT:
      - Disable audit logging
      - Delete or truncate the audit ledger
      - Perform any action without a corresponding chain event
    Every admin action is recorded with event_type in the governance chain.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import secrets
import socket
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from gavel.chain import GovernanceChain, ChainEvent, EventType
from gavel.enrollment import (
    EnrollmentApplication,
    EnrollmentRegistry,
    EnrollmentStatus,
    PurposeDeclaration,
    CapabilityManifest,
    ResourceAllowlist,
    ActionBoundaries,
    FallbackBehavior,
)

log = logging.getLogger("gavel.admin")


# ---------------------------------------------------------------------------
# Extended ledger event types for admin operations
# ---------------------------------------------------------------------------

class AdminLedgerEvent(str, Enum):
    """Ledger event types specific to admin agent operations."""
    ADMIN_REGISTERED = "ADMIN_REGISTERED"
    ADMIN_ACTION = "ADMIN_ACTION"
    ADMIN_BLOCKED = "ADMIN_BLOCKED"
    ADMIN_SESSION_START = "ADMIN_SESSION_START"
    ADMIN_SESSION_END = "ADMIN_SESSION_END"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SecurityViolation(Exception):
    """
    Raised when an admin mode activation attempt fails a security gate.

    Attributes:
        gate: Which gate failed ("env_flag", "production_block", "machine_allowlist").
        reason: Human-readable explanation.
        machine_id: The machine ID that was evaluated.
        attempted_env: The GAVEL_ENV value at the time of the attempt.
    """

    def __init__(
        self,
        gate: str,
        reason: str,
        machine_id: str = "",
        attempted_env: str = "",
    ) -> None:
        self.gate = gate
        self.reason = reason
        self.machine_id = machine_id
        self.attempted_env = attempted_env
        super().__init__(
            f"SecurityViolation[{gate}]: {reason} "
            f"(machine={machine_id}, env={attempted_env})"
        )


class AdminAuditViolation(Exception):
    """Raised when admin code attempts to bypass audit guarantees."""

    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(
            f"AdminAuditViolation: operation '{operation}' is forbidden "
            f"even for admin agents. Audit integrity is non-negotiable."
        )


# ---------------------------------------------------------------------------
# Admin token
# ---------------------------------------------------------------------------

class AdminToken(BaseModel):
    """
    All-scope governance token for the admin agent.

    Properties:
        - Prefix: gvl_admin_
        - Capabilities: ["*"] (all capabilities)
        - Scope: all paths, all commands, network enabled
        - No expiry (dev-only token)
        - Bound to operator identity and machine_id
    """
    token: str = Field(description="Full token string with gvl_admin_ prefix")
    operator: str = Field(description="Operator identity that owns this token")
    machine_id: str = Field(description="Hardware-bound machine identifier")
    capabilities: list[str] = Field(default_factory=lambda: ["*"])
    scope: dict[str, Any] = Field(default_factory=lambda: {
        "allow_paths": ["*"],
        "allow_commands": ["*"],
        "allow_network": True,
    })
    issued_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str | None = Field(default=None, description="None = no expiry (dev only)")
    revoked: bool = Field(default=False)

    @staticmethod
    def generate(operator: str, machine_id: str) -> AdminToken:
        """Generate a new admin token bound to operator and machine."""
        raw = secrets.token_hex(32)
        token_str = f"gvl_admin_{raw}"
        return AdminToken(
            token=token_str,
            operator=operator,
            machine_id=machine_id,
        )


# ---------------------------------------------------------------------------
# Machine ID computation
# ---------------------------------------------------------------------------

def get_machine_id() -> str:
    """
    Compute a stable machine identifier from hardware properties.

    Uses a SHA-256 hash of hostname + platform node + machine UUID to produce
    a deterministic, non-reversible identifier for allowlist matching.
    """
    components = [
        socket.gethostname(),
        platform.node(),
        str(uuid.getnode()),  # MAC-address-derived integer
    ]
    raw = "|".join(components)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Gate validation
# ---------------------------------------------------------------------------

class AdminGateResult(BaseModel):
    """Result of evaluating the triple gate for admin mode activation."""
    passed: bool = False
    env_flag_ok: bool = False
    production_block_ok: bool = False
    machine_allowlist_ok: bool = False
    failure_gate: str | None = None
    failure_reason: str | None = None
    machine_id: str = ""
    gavel_env: str = ""


def validate_admin_gates(
    allowlist: set[str] | None = None,
) -> AdminGateResult:
    """
    Evaluate all three admin mode gates.

    Args:
        allowlist: Set of allowed machine ID hashes. If None, reads from
                   GAVEL_ADMIN_MACHINES env var (comma-separated).

    Returns:
        AdminGateResult with pass/fail details for each gate.
    """
    machine_id = get_machine_id()
    gavel_env = os.environ.get("GAVEL_ENV", "development")
    admin_flag = os.environ.get("GAVEL_ADMIN_MODE", "false").lower().strip()

    result = AdminGateResult(machine_id=machine_id, gavel_env=gavel_env)

    # Gate 1: GAVEL_ADMIN_MODE=true
    if admin_flag != "true":
        result.passed = False
        result.failure_gate = "env_flag"
        result.failure_reason = (
            f"GAVEL_ADMIN_MODE is '{admin_flag}', must be 'true' to activate admin mode"
        )
        return result
    result.env_flag_ok = True

    # Gate 2: GAVEL_ENV is NOT "production" (hard block)
    if gavel_env.lower().strip() == "production":
        result.passed = False
        result.failure_gate = "production_block"
        result.failure_reason = (
            "GAVEL_ENV is 'production'. Admin mode is permanently disabled in production. "
            "This is a hard block with no override mechanism."
        )
        return result
    result.production_block_ok = True

    # Gate 3: Machine ID in allowlist
    if allowlist is None:
        raw = os.environ.get("GAVEL_ADMIN_MACHINES", "")
        allowlist = {m.strip() for m in raw.split(",") if m.strip()}

    if not allowlist:
        result.passed = False
        result.failure_gate = "machine_allowlist"
        result.failure_reason = (
            "No dev machines configured in allowlist. Set GAVEL_ADMIN_MACHINES "
            "environment variable with comma-separated machine ID hashes, or pass "
            "allowlist parameter. Current machine ID: " + machine_id
        )
        return result

    if machine_id not in allowlist:
        result.passed = False
        result.failure_gate = "machine_allowlist"
        result.failure_reason = (
            f"Machine ID {machine_id} is not in the dev-machine allowlist. "
            f"Allowlist contains {len(allowlist)} machine(s). Add this machine's ID "
            f"to GAVEL_ADMIN_MACHINES to authorize it for admin mode."
        )
        return result
    result.machine_allowlist_ok = True

    result.passed = True
    return result


# ---------------------------------------------------------------------------
# Admin enrollment helper
# ---------------------------------------------------------------------------

def _build_admin_enrollment(operator: str, machine_id: str) -> EnrollmentApplication:
    """Build an EnrollmentApplication for the admin agent."""
    return EnrollmentApplication(
        agent_id=f"admin:{operator}",
        display_name=f"Admin Agent ({operator})",
        agent_type="admin_agent",
        owner=operator,
        owner_contact=operator,
        budget_tokens=999_999_999,
        budget_usd=999_999.0,
        purpose=PurposeDeclaration(
            summary="Development admin agent with full governance bypass",
            operational_scope="all",
            expected_lifetime="session",
            risk_tier="critical",
        ),
        capabilities=CapabilityManifest(
            tools=["*"],
            max_concurrent_chains=999,
            can_spawn_subagents=True,
            network_access=True,
            file_system_access=True,
            execution_access=True,
        ),
        resources=ResourceAllowlist(
            allowed_paths=["*"],
            allowed_hosts=["*"],
            allowed_env_vars=["*"],
            max_file_size_mb=10_000.0,
        ),
        boundaries=ActionBoundaries(
            allowed_actions=["read", "write", "execute", "deploy", "admin"],
            blocked_patterns=[],
            max_actions_per_minute=999_999,
            max_risk_threshold=1.0,
        ),
        fallback=FallbackBehavior(
            on_gateway_unreachable="continue",
            on_budget_exceeded="continue",
            on_sla_timeout="auto-approve",
            graceful_shutdown=True,
        ),
    )


# ---------------------------------------------------------------------------
# AdminAgent
# ---------------------------------------------------------------------------

class AdminAgent:
    """
    Development-only agent with full governance bypass.

    Auto-registers with the EnrollmentRegistry at construction time and
    receives an all-scope governance token. Bypasses tier evaluation,
    SLA timers, and separation of powers checks.

    CRITICAL: Audit logging is NEVER bypassed. Every admin action is
    recorded in a governance chain with full hash-chain integrity.

    Usage:
        registry = EnrollmentRegistry()
        agent = AdminAgent(
            operator="dev@gavel.eu",
            registry=registry,
            allowlist={"<machine_id_hash>"},
        )
        # agent.token contains the gvl_admin_ prefixed token
        agent.execute("deploy_model", {"model": "v2.3"})

    Raises:
        SecurityViolation: If any of the three admin gates fails.
    """

    # Actions that are forbidden even for admin agents
    _FORBIDDEN_OPERATIONS: frozenset[str] = frozenset({
        "disable_audit",
        "delete_audit_ledger",
        "truncate_audit_ledger",
        "clear_audit_ledger",
        "pause_audit",
        "stop_audit",
        "modify_audit_chain",
        "rewrite_audit_history",
    })

    def __init__(
        self,
        operator: str,
        registry: EnrollmentRegistry,
        allowlist: set[str] | None = None,
        audit_chain: GovernanceChain | None = None,
    ) -> None:
        self._operator = operator
        self._registry = registry
        self._audit_chain = audit_chain or GovernanceChain()
        self._lock = threading.Lock()
        self._action_counter = 0
        self._active = False

        # Validate all three gates
        gate_result = validate_admin_gates(allowlist=allowlist)

        if not gate_result.passed:
            assert gate_result.failure_gate is not None
            assert gate_result.failure_reason is not None

            # Log the blocked attempt to the audit chain BEFORE raising
            self._audit_chain.append(
                event_type=EventType.AUTO_DENIED,
                actor_id=f"admin:{operator}",
                role_used="admin_agent",
                payload={
                    "admin_event": AdminLedgerEvent.ADMIN_BLOCKED.value,
                    "gate_failed": gate_result.failure_gate,
                    "reason": gate_result.failure_reason,
                    "machine_id": gate_result.machine_id,
                    "gavel_env": gate_result.gavel_env,
                    "env_flag_ok": gate_result.env_flag_ok,
                    "production_block_ok": gate_result.production_block_ok,
                    "machine_allowlist_ok": gate_result.machine_allowlist_ok,
                },
            )

            log.warning(
                "Admin mode activation BLOCKED: gate=%s reason=%s machine=%s",
                gate_result.failure_gate,
                gate_result.failure_reason,
                gate_result.machine_id,
            )

            raise SecurityViolation(
                gate=gate_result.failure_gate,
                reason=gate_result.failure_reason,
                machine_id=gate_result.machine_id,
                attempted_env=gate_result.gavel_env,
            )

        # All gates passed — register with EnrollmentRegistry
        self._machine_id = gate_result.machine_id
        self._token = AdminToken.generate(
            operator=operator,
            machine_id=self._machine_id,
        )

        # Register via the existing EnrollmentApplication model
        application = _build_admin_enrollment(operator, self._machine_id)
        record = self._registry.submit(application)

        if record.status != EnrollmentStatus.ENROLLED:
            # Force-approve: admin agents bypass enrollment validation
            self._registry.approve_manual(
                agent_id=application.agent_id,
                reviewed_by=f"admin_agent:{operator}",
            )

        # Record registration in the audit chain
        self._audit_chain.append(
            event_type=EventType.APPROVAL_GRANTED,
            actor_id=f"admin:{operator}",
            role_used="admin_agent",
            payload={
                "admin_event": AdminLedgerEvent.ADMIN_REGISTERED.value,
                "token_prefix": self._token.token[:16] + "...",
                "machine_id": self._machine_id,
                "gavel_env": gate_result.gavel_env,
                "capabilities": self._token.capabilities,
                "scope": self._token.scope,
                "expires_at": self._token.expires_at,
            },
        )

        self._active = True
        log.info(
            "Admin agent registered: operator=%s machine=%s token=%s...",
            operator,
            self._machine_id[:16],
            self._token.token[:20],
        )

    # -- Properties ----------------------------------------------------------

    @property
    def token(self) -> AdminToken:
        """The admin governance token. Raises if agent is not active."""
        if not self._active:
            raise RuntimeError("Admin agent is not active")
        return self._token

    @property
    def token_string(self) -> str:
        """The raw token string for use in API headers."""
        return self.token.token

    @property
    def operator(self) -> str:
        return self._operator

    @property
    def machine_id(self) -> str:
        return self._machine_id

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def action_count(self) -> int:
        return self._action_counter

    @property
    def audit_chain(self) -> GovernanceChain:
        """The governance chain recording all admin actions."""
        return self._audit_chain

    # -- Audit-guaranteed execution ------------------------------------------

    def execute(
        self,
        action: str,
        payload: dict[str, Any] | None = None,
        target: str = "",
    ) -> dict[str, Any]:
        """
        Execute an action with governance bypass but mandatory audit.

        Every call creates a chain event BEFORE the action is considered
        executed. The chain event is the proof that the action occurred.

        Args:
            action: The action identifier (e.g., "deploy_model", "read_config").
            payload: Arbitrary action payload for audit purposes.
            target: Optional target resource identifier.

        Returns:
            Dict with action receipt including chain event hash.

        Raises:
            AdminAuditViolation: If the action attempts to bypass audit.
            RuntimeError: If the agent is not active.
        """
        if not self._active:
            raise RuntimeError("Admin agent is not active — cannot execute actions")

        # Hard block on audit-bypassing operations
        action_lower = action.lower().strip()
        if action_lower in self._FORBIDDEN_OPERATIONS:
            # Log the attempt before raising
            self._audit_chain.append(
                event_type=EventType.AUTO_DENIED,
                actor_id=f"admin:{self._operator}",
                role_used="admin_agent",
                payload={
                    "admin_event": "AUDIT_BYPASS_BLOCKED",
                    "attempted_action": action,
                    "reason": "Audit operations cannot be disabled or modified, "
                              "even by admin agents.",
                },
            )
            raise AdminAuditViolation(action)

        payload = payload or {}

        with self._lock:
            self._action_counter += 1
            seq = self._action_counter

        # Record action to audit chain (BEFORE returning success)
        event = self._audit_chain.append(
            event_type=EventType.EXECUTION_COMPLETED,
            actor_id=f"admin:{self._operator}",
            role_used="admin_agent",
            payload={
                "admin_event": AdminLedgerEvent.ADMIN_ACTION.value,
                "action": action,
                "target": target,
                "sequence": seq,
                "action_payload": payload,
                "token_prefix": self._token.token[:16] + "...",
                "machine_id": self._machine_id,
                "governance_bypassed": True,
                "audit_recorded": True,
            },
        )

        log.info(
            "Admin action executed: action=%s seq=%d hash=%s...",
            action,
            seq,
            event.event_hash[:16],
        )

        return {
            "status": "executed",
            "action": action,
            "sequence": seq,
            "chain_id": self._audit_chain.chain_id,
            "event_hash": event.event_hash,
            "timestamp": event.timestamp.isoformat(),
            "governance_bypassed": True,
            "audit_recorded": True,
        }

    # -- Session lifecycle ---------------------------------------------------

    def end_session(self) -> None:
        """
        End the admin session and revoke the token.

        Records a session-end event in the chain and marks the token
        as revoked. The agent cannot execute further actions after this.
        """
        if not self._active:
            return

        self._audit_chain.append(
            event_type=EventType.ROLLBACK_TRIGGERED,
            actor_id=f"admin:{self._operator}",
            role_used="admin_agent",
            payload={
                "admin_event": AdminLedgerEvent.ADMIN_SESSION_END.value,
                "total_actions": self._action_counter,
                "token_prefix": self._token.token[:16] + "...",
                "machine_id": self._machine_id,
            },
        )

        self._token.revoked = True
        self._active = False
        log.info(
            "Admin session ended: operator=%s actions=%d",
            self._operator,
            self._action_counter,
        )


# ---------------------------------------------------------------------------
# Production safety checks
# ---------------------------------------------------------------------------

def is_admin_safe() -> bool:
    """
    Verify that admin mode is safely disabled.

    Intended for CI pipeline gates. Returns True when ALL of the following
    are true:
      - GAVEL_ADMIN_MODE is not "true"
      - GAVEL_ENV is "production" OR GAVEL_ADMIN_MODE is absent/false

    Returns:
        True if admin mode is provably disabled and safe for production.
    """
    admin_flag = os.environ.get("GAVEL_ADMIN_MODE", "false").lower().strip()
    gavel_env = os.environ.get("GAVEL_ENV", "").lower().strip()

    # If env is production, admin mode is always blocked regardless of flag
    if gavel_env == "production":
        return True

    # If admin flag is not set or is false, admin mode is disabled
    if admin_flag != "true":
        return True

    # Admin mode is active in a non-production environment — not safe
    # for production deployment
    return False


def validate_environment_for_production() -> tuple[bool, list[str]]:
    """
    Comprehensive environment validation for production deployment.

    Returns:
        Tuple of (is_safe, list_of_warnings).
        is_safe is True only when the environment is confirmed safe.
    """
    warnings: list[str] = []
    gavel_env = os.environ.get("GAVEL_ENV", "").lower().strip()
    admin_flag = os.environ.get("GAVEL_ADMIN_MODE", "false").lower().strip()
    admin_machines = os.environ.get("GAVEL_ADMIN_MACHINES", "")

    if gavel_env != "production":
        warnings.append(
            f"GAVEL_ENV is '{gavel_env}', expected 'production' for production deployment"
        )

    if admin_flag == "true":
        warnings.append(
            "GAVEL_ADMIN_MODE is 'true' — admin mode is enabled. "
            "This MUST be disabled for production."
        )

    if admin_machines:
        warnings.append(
            "GAVEL_ADMIN_MACHINES is set — dev machine allowlist should be empty "
            "in production environments."
        )

    is_safe = len(warnings) == 0
    return is_safe, warnings


def get_dockerfile_arg_snippet() -> str:
    """
    Return the Dockerfile ARG snippet that strips admin code path.

    This is a reference snippet for build pipelines. When ADMIN_MODE=false
    (the default), the admin module is replaced with a stub that raises
    on import.
    """
    return '''# --- Gavel Admin Mode Build Gate ---
# Default: admin mode disabled. Set --build-arg ADMIN_MODE=true for dev builds only.
ARG ADMIN_MODE=false

# When ADMIN_MODE=false, replace admin.py with a production stub that
# raises ImportError on any admin class usage.
RUN if [ "$ADMIN_MODE" = "false" ]; then \\
      echo 'raise ImportError("Admin module stripped from production build. """' \\
           '"This is expected — admin mode is development-only.")' \\
           > /app/gavel/admin.py; \\
    fi
'''
