"""
Role-based and attribute-based access control for operators.

Gavel enforces agent-side separation of powers (proposer ≠ reviewer ≠
approver). This module extends that to operator-side access control:
*which humans* may do *which governance operations*.

Two layers:

  1. RBAC — fixed roles with coarse permission bundles:

       viewer           read dashboards, read audit trail
       operator         enroll agents, approve chains, run readiness checks
       auditor          everything read-only + export compliance bundles
       security_officer revoke tokens, enable kill switch, suspend agents
       admin            full surface (typically break-glass only)

  2. ABAC — attribute predicates evaluated on top of the base role.
     Attributes come from the request context (tenant_id, time_of_day,
     classification, source_ip_category). A grant is reached only if
     BOTH the role allows the permission AND every attribute predicate
     attached to that role evaluates true.

Design notes:

  - Pure-Python, deterministic, no external dependency. ABAC rules are
    expressed as `AttributePredicate` records whose evaluation is a
    plain comparison on the attribute dict — we do not accept arbitrary
    Python expressions from config.
  - Every access decision is a structured `AccessDecision` with the
    rule that granted or denied it, suitable for logging into the
    governance chain.
  - The default policy (see `default_policy()`) implements the table
    above as a concrete starting point. Deployers can replace it
    wholesale or extend it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Role and permission vocabulary ─────────────────────────────

class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    SECURITY_OFFICER = "security_officer"
    ADMIN = "admin"


class Permission(str, Enum):
    # Read
    READ_DASHBOARD = "read:dashboard"
    READ_CHAIN = "read:chain"
    READ_ENROLLMENT = "read:enrollment"
    READ_INCIDENT = "read:incident"

    # Operate
    ENROLL_AGENT = "enroll:agent"
    APPROVE_CHAIN = "approve:chain"
    EXECUTE_CHAIN = "execute:chain"
    RUN_READINESS = "run:readiness"

    # Security
    REVOKE_TOKEN = "revoke:token"
    SUSPEND_AGENT = "suspend:agent"
    ENGAGE_KILLSWITCH = "engage:killswitch"

    # Compliance
    EXPORT_BUNDLE = "export:bundle"
    REPORT_INCIDENT = "report:incident"
    RESOLVE_INCIDENT = "resolve:incident"

    # Admin
    MANAGE_POLICY = "manage:policy"
    MANAGE_OPERATOR = "manage:operator"


# ── ABAC predicate ─────────────────────────────────────────────

class AttributeOp(str, Enum):
    EQ = "eq"
    NEQ = "neq"
    IN = "in"
    NOT_IN = "not_in"
    GTE = "gte"
    LTE = "lte"


class AttributePredicate(BaseModel):
    """A single attribute check against the request context."""

    attribute: str                    # key in the context dict
    op: AttributeOp
    value: Any                        # scalar or list, depending on op

    def evaluate(self, ctx: dict[str, Any]) -> tuple[bool, str]:
        if self.attribute not in ctx:
            return False, f"attribute '{self.attribute}' missing from context"
        actual = ctx[self.attribute]
        if self.op == AttributeOp.EQ:
            ok = actual == self.value
        elif self.op == AttributeOp.NEQ:
            ok = actual != self.value
        elif self.op == AttributeOp.IN:
            ok = actual in (self.value or [])
        elif self.op == AttributeOp.NOT_IN:
            ok = actual not in (self.value or [])
        elif self.op == AttributeOp.GTE:
            ok = actual >= self.value
        elif self.op == AttributeOp.LTE:
            ok = actual <= self.value
        else:  # pragma: no cover — enum guarantees coverage
            return False, f"unknown op {self.op}"
        return ok, "" if ok else (
            f"attribute '{self.attribute}' {self.op.value} {self.value!r} "
            f"failed (got {actual!r})"
        )


class AccessRule(BaseModel):
    """One role→permission grant with optional ABAC constraints."""

    role: Role
    permission: Permission
    predicates: list[AttributePredicate] = Field(default_factory=list)
    description: str = ""


class AccessPolicy(BaseModel):
    """A complete access policy (set of rules)."""

    rules: list[AccessRule] = Field(default_factory=list)

    def rules_for(self, role: Role, permission: Permission) -> list[AccessRule]:
        return [
            r for r in self.rules
            if r.role == role and r.permission == permission
        ]


# ── Decision ───────────────────────────────────────────────────

class AccessDecision(BaseModel):
    """Structured decision, safe to write to the governance chain."""

    operator_id: str
    roles: list[Role]
    permission: Permission
    allowed: bool
    reason: str
    matched_rule_index: Optional[int] = None
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AccessDeniedError(PermissionError):
    """PermissionError carrying a structured :class:`AccessDecision`."""

    def __init__(self, reason: str, decision: AccessDecision) -> None:
        super().__init__(reason)
        self.decision = decision


# ── Default policy ─────────────────────────────────────────────

def default_policy() -> AccessPolicy:
    """Gavel's out-of-the-box role→permission table."""
    read_perms = [
        Permission.READ_DASHBOARD,
        Permission.READ_CHAIN,
        Permission.READ_ENROLLMENT,
        Permission.READ_INCIDENT,
    ]
    operator_perms = read_perms + [
        Permission.ENROLL_AGENT,
        Permission.APPROVE_CHAIN,
        Permission.EXECUTE_CHAIN,
        Permission.RUN_READINESS,
        Permission.REPORT_INCIDENT,
    ]
    auditor_perms = read_perms + [
        Permission.EXPORT_BUNDLE,
        Permission.REPORT_INCIDENT,
    ]
    security_perms = read_perms + [
        Permission.REVOKE_TOKEN,
        Permission.SUSPEND_AGENT,
        Permission.ENGAGE_KILLSWITCH,
        Permission.REPORT_INCIDENT,
        Permission.RESOLVE_INCIDENT,
    ]
    admin_perms = list(Permission)

    rules: list[AccessRule] = []
    for role, perms in (
        (Role.VIEWER, read_perms),
        (Role.OPERATOR, operator_perms),
        (Role.AUDITOR, auditor_perms),
        (Role.SECURITY_OFFICER, security_perms),
        (Role.ADMIN, admin_perms),
    ):
        for p in perms:
            rules.append(AccessRule(
                role=role,
                permission=p,
                description=f"{role.value} may {p.value}",
            ))
    return AccessPolicy(rules=rules)


# ── Access checker ─────────────────────────────────────────────

class AccessChecker:
    """Evaluate access requests against a policy."""

    def __init__(self, policy: Optional[AccessPolicy] = None):
        self._policy = policy or default_policy()

    @property
    def policy(self) -> AccessPolicy:
        return self._policy

    def check(
        self,
        *,
        operator_id: str,
        roles: list[Role],
        permission: Permission,
        context: Optional[dict[str, Any]] = None,
    ) -> AccessDecision:
        context = context or {}
        if not roles:
            return AccessDecision(
                operator_id=operator_id,
                roles=[],
                permission=permission,
                allowed=False,
                reason="operator has no roles assigned",
            )

        # Look for any rule, under any of the operator's roles, that
        # grants this permission AND whose ABAC predicates all pass.
        first_failure: Optional[str] = None
        for role in roles:
            for idx, rule in enumerate(self._policy.rules):
                if rule.role != role or rule.permission != permission:
                    continue
                ok = True
                predicate_failure: Optional[str] = None
                for pred in rule.predicates:
                    passed, msg = pred.evaluate(context)
                    if not passed:
                        ok = False
                        predicate_failure = msg
                        break
                if ok:
                    return AccessDecision(
                        operator_id=operator_id,
                        roles=roles,
                        permission=permission,
                        allowed=True,
                        reason=f"rule[{idx}] {role.value}→{permission.value}",
                        matched_rule_index=idx,
                    )
                if first_failure is None and predicate_failure:
                    first_failure = (
                        f"rule[{idx}] {role.value}→{permission.value} denied: "
                        f"{predicate_failure}"
                    )

        reason = first_failure or (
            f"no rule grants {permission.value} to roles "
            f"{[r.value for r in roles]}"
        )
        return AccessDecision(
            operator_id=operator_id,
            roles=roles,
            permission=permission,
            allowed=False,
            reason=reason,
        )

    def require(
        self,
        *,
        operator_id: str,
        roles: list[Role],
        permission: Permission,
        context: Optional[dict[str, Any]] = None,
    ) -> AccessDecision:
        """Like check, but raises PermissionError on deny.

        Use at the top of any operator-facing handler that mutates
        state; the raised error is catchable and the decision record
        can still be logged via the exception's .decision attribute.
        """
        decision = self.check(
            operator_id=operator_id,
            roles=roles,
            permission=permission,
            context=context,
        )
        if not decision.allowed:
            raise AccessDeniedError(decision.reason, decision)
        return decision
