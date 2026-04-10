"""Tests for gavel.rbac — operator RBAC/ABAC."""

from __future__ import annotations

import pytest

from gavel.rbac import (
    AccessChecker,
    AccessPolicy,
    AccessRule,
    AttributeOp,
    AttributePredicate,
    Permission,
    Role,
    default_policy,
)


class TestDefaultPolicy:
    def test_viewer_can_read_but_not_enroll(self):
        ac = AccessChecker()
        ok = ac.check(
            operator_id="op:alice",
            roles=[Role.VIEWER],
            permission=Permission.READ_DASHBOARD,
        )
        assert ok.allowed
        denied = ac.check(
            operator_id="op:alice",
            roles=[Role.VIEWER],
            permission=Permission.ENROLL_AGENT,
        )
        assert not denied.allowed
        assert "no rule grants" in denied.reason

    def test_operator_can_enroll_and_execute(self):
        ac = AccessChecker()
        assert ac.check(
            operator_id="op:bob",
            roles=[Role.OPERATOR],
            permission=Permission.ENROLL_AGENT,
        ).allowed
        assert ac.check(
            operator_id="op:bob",
            roles=[Role.OPERATOR],
            permission=Permission.EXECUTE_CHAIN,
        ).allowed

    def test_operator_cannot_engage_killswitch(self):
        ac = AccessChecker()
        d = ac.check(
            operator_id="op:bob",
            roles=[Role.OPERATOR],
            permission=Permission.ENGAGE_KILLSWITCH,
        )
        assert not d.allowed

    def test_security_officer_can_killswitch_and_revoke(self):
        ac = AccessChecker()
        assert ac.check(
            operator_id="op:sec",
            roles=[Role.SECURITY_OFFICER],
            permission=Permission.ENGAGE_KILLSWITCH,
        ).allowed
        assert ac.check(
            operator_id="op:sec",
            roles=[Role.SECURITY_OFFICER],
            permission=Permission.REVOKE_TOKEN,
        ).allowed

    def test_auditor_can_export_bundle(self):
        ac = AccessChecker()
        assert ac.check(
            operator_id="op:aud",
            roles=[Role.AUDITOR],
            permission=Permission.EXPORT_BUNDLE,
        ).allowed

    def test_auditor_cannot_enroll(self):
        ac = AccessChecker()
        assert not ac.check(
            operator_id="op:aud",
            roles=[Role.AUDITOR],
            permission=Permission.ENROLL_AGENT,
        ).allowed

    def test_admin_has_everything(self):
        ac = AccessChecker()
        for perm in Permission:
            assert ac.check(
                operator_id="op:root",
                roles=[Role.ADMIN],
                permission=perm,
            ).allowed, f"admin denied {perm}"

    def test_empty_roles_denied(self):
        ac = AccessChecker()
        d = ac.check(
            operator_id="op:nobody",
            roles=[],
            permission=Permission.READ_DASHBOARD,
        )
        assert not d.allowed
        assert "no roles" in d.reason

    def test_union_of_multiple_roles(self):
        ac = AccessChecker()
        d = ac.check(
            operator_id="op:dual",
            roles=[Role.VIEWER, Role.SECURITY_OFFICER],
            permission=Permission.ENGAGE_KILLSWITCH,
        )
        assert d.allowed


class TestABAC:
    def test_predicate_equality(self):
        policy = AccessPolicy(rules=[
            AccessRule(
                role=Role.OPERATOR,
                permission=Permission.APPROVE_CHAIN,
                predicates=[AttributePredicate(
                    attribute="tenant_id", op=AttributeOp.EQ, value="acme"
                )],
            ),
        ])
        ac = AccessChecker(policy=policy)
        assert ac.check(
            operator_id="op:x",
            roles=[Role.OPERATOR],
            permission=Permission.APPROVE_CHAIN,
            context={"tenant_id": "acme"},
        ).allowed
        d = ac.check(
            operator_id="op:x",
            roles=[Role.OPERATOR],
            permission=Permission.APPROVE_CHAIN,
            context={"tenant_id": "other"},
        )
        assert not d.allowed
        assert "acme" in d.reason

    def test_predicate_in_list(self):
        policy = AccessPolicy(rules=[
            AccessRule(
                role=Role.OPERATOR,
                permission=Permission.EXECUTE_CHAIN,
                predicates=[AttributePredicate(
                    attribute="classification",
                    op=AttributeOp.IN,
                    value=["public", "internal"],
                )],
            ),
        ])
        ac = AccessChecker(policy=policy)
        assert ac.check(
            operator_id="op:x",
            roles=[Role.OPERATOR],
            permission=Permission.EXECUTE_CHAIN,
            context={"classification": "internal"},
        ).allowed
        assert not ac.check(
            operator_id="op:x",
            roles=[Role.OPERATOR],
            permission=Permission.EXECUTE_CHAIN,
            context={"classification": "secret"},
        ).allowed

    def test_predicate_numeric_gte(self):
        policy = AccessPolicy(rules=[
            AccessRule(
                role=Role.OPERATOR,
                permission=Permission.APPROVE_CHAIN,
                predicates=[AttributePredicate(
                    attribute="trust_score", op=AttributeOp.GTE, value=0.8
                )],
            ),
        ])
        ac = AccessChecker(policy=policy)
        assert ac.check(
            operator_id="op:x",
            roles=[Role.OPERATOR],
            permission=Permission.APPROVE_CHAIN,
            context={"trust_score": 0.9},
        ).allowed
        assert not ac.check(
            operator_id="op:x",
            roles=[Role.OPERATOR],
            permission=Permission.APPROVE_CHAIN,
            context={"trust_score": 0.5},
        ).allowed

    def test_missing_attribute_denies(self):
        policy = AccessPolicy(rules=[
            AccessRule(
                role=Role.OPERATOR,
                permission=Permission.APPROVE_CHAIN,
                predicates=[AttributePredicate(
                    attribute="tenant_id", op=AttributeOp.EQ, value="acme"
                )],
            ),
        ])
        ac = AccessChecker(policy=policy)
        d = ac.check(
            operator_id="op:x",
            roles=[Role.OPERATOR],
            permission=Permission.APPROVE_CHAIN,
            context={},
        )
        assert not d.allowed
        assert "tenant_id" in d.reason

    def test_multiple_predicates_all_must_pass(self):
        policy = AccessPolicy(rules=[
            AccessRule(
                role=Role.OPERATOR,
                permission=Permission.EXECUTE_CHAIN,
                predicates=[
                    AttributePredicate(
                        attribute="tenant_id", op=AttributeOp.EQ, value="acme"
                    ),
                    AttributePredicate(
                        attribute="trust_score", op=AttributeOp.GTE, value=0.5
                    ),
                ],
            ),
        ])
        ac = AccessChecker(policy=policy)
        assert ac.check(
            operator_id="op:x",
            roles=[Role.OPERATOR],
            permission=Permission.EXECUTE_CHAIN,
            context={"tenant_id": "acme", "trust_score": 0.9},
        ).allowed
        # one predicate fails
        assert not ac.check(
            operator_id="op:x",
            roles=[Role.OPERATOR],
            permission=Permission.EXECUTE_CHAIN,
            context={"tenant_id": "acme", "trust_score": 0.1},
        ).allowed


class TestRequire:
    def test_require_raises_on_deny(self):
        ac = AccessChecker()
        with pytest.raises(PermissionError) as exc:
            ac.require(
                operator_id="op:alice",
                roles=[Role.VIEWER],
                permission=Permission.ENROLL_AGENT,
            )
        assert hasattr(exc.value, "decision")
        assert exc.value.decision.allowed is False  # type: ignore[attr-defined]

    def test_require_returns_decision_on_allow(self):
        ac = AccessChecker()
        d = ac.require(
            operator_id="op:bob",
            roles=[Role.OPERATOR],
            permission=Permission.ENROLL_AGENT,
        )
        assert d.allowed


class TestDefaultPolicyShape:
    def test_every_role_has_at_least_one_rule(self):
        policy = default_policy()
        for role in Role:
            assert any(r.role == role for r in policy.rules), \
                f"{role} has no rules"

    def test_admin_covers_all_permissions(self):
        policy = default_policy()
        admin_perms = {r.permission for r in policy.rules if r.role == Role.ADMIN}
        assert admin_perms == set(Permission)
