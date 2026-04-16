"""Baseline — create all seven Wave 1 tables.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-04-14

Creates:

* governance_chains
* chain_events         (FK -> governance_chains.chain_id)
* agents
* enrollment_tokens
* incidents
* evidence_packets
* review_results
* execution_tokens

Downgrade drops all eight tables (chain_events must go before
governance_chains to respect the FK).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "0001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "governance_chains",
        sa.Column("chain_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="PENDING"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_roles", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("chain_id"),
    )

    op.create_table(
        "chain_events",
        sa.Column("chain_id", sa.String(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("role_used", sa.String(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("prev_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column("event_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column("request_id", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["chain_id"], ["governance_chains.chain_id"]),
        sa.PrimaryKeyConstraint("chain_id", "sequence"),
    )
    op.create_index("ix_chain_events_event_id", "chain_events", ["event_id"])

    op.create_table(
        "agents",
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("display_name", sa.String(), nullable=False),
        sa.Column("agent_type", sa.String(), nullable=False),
        sa.Column("did", sa.String(), nullable=False, server_default=""),
        sa.Column("trust_score", sa.Integer(), nullable=False, server_default="500"),
        sa.Column("autonomy_tier", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="ACTIVE"),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_interval_s", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("chains_proposed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("chains_completed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("violations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("successful_actions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("session_id", sa.String(), nullable=False, server_default=""),
        sa.Column("current_activity", sa.String(), nullable=False, server_default="Idle"),
        sa.PrimaryKeyConstraint("agent_id"),
    )

    op.create_table(
        "enrollment_tokens",
        sa.Column("token", sa.String(), nullable=False),
        sa.Column("agent_did", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ttl_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("scope", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("token"),
    )
    op.create_index("ix_enrollment_tokens_agent_did", "enrollment_tokens", ["agent_did"])
    op.create_index("ix_enrollment_tokens_agent_id", "enrollment_tokens", ["agent_id"])

    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("chain_ids", sa.JSON(), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column("regulatory_references", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("incident_id"),
    )
    op.create_index("ix_incidents_agent_id", "incidents", ["agent_id"])

    op.create_table(
        "evidence_packets",
        sa.Column("packet_id", sa.String(), nullable=False),
        sa.Column("chain_id", sa.String(), nullable=False, server_default=""),
        sa.Column("intent_event_id", sa.String(), nullable=False, server_default=""),
        sa.Column("command_argv", sa.JSON(), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=False, server_default="-1"),
        sa.Column("stdout_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column("stderr_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column("diff_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column("stdout_preview", sa.Text(), nullable=False, server_default=""),
        sa.Column("files_modified", sa.JSON(), nullable=False),
        sa.Column("files_created", sa.JSON(), nullable=False),
        sa.Column("files_deleted", sa.JSON(), nullable=False),
        sa.Column("image", sa.String(), nullable=False, server_default=""),
        sa.Column("image_digest", sa.String(), nullable=False, server_default=""),
        sa.Column("network_mode", sa.String(), nullable=False, server_default="none"),
        sa.Column("cpu", sa.String(), nullable=False, server_default="1"),
        sa.Column("memory", sa.String(), nullable=False, server_default="512m"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("packet_id"),
    )
    op.create_index("ix_evidence_packets_chain_id", "evidence_packets", ["chain_id"])

    op.create_table(
        "review_results",
        sa.Column("packet_id", sa.String(), nullable=False),
        sa.Column("chain_id", sa.String(), nullable=False, server_default=""),
        sa.Column("verdict", sa.String(), nullable=False, server_default="PASS"),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column("risk_delta", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("scope_compliance", sa.String(), nullable=False, server_default="FULL"),
        sa.Column("review_hash", sa.Text(), nullable=False, server_default=""),
        sa.Column("redacted_stdout", sa.Text(), nullable=False, server_default=""),
        sa.Column("redacted_stderr", sa.Text(), nullable=False, server_default=""),
        sa.Column("privacy_findings", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("packet_id"),
    )
    op.create_index("ix_review_results_chain_id", "review_results", ["chain_id"])

    op.create_table(
        "execution_tokens",
        sa.Column("token_id", sa.String(), nullable=False),
        sa.Column("chain_id", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.PrimaryKeyConstraint("token_id"),
    )
    op.create_index("ix_execution_tokens_chain_id", "execution_tokens", ["chain_id"])


def downgrade() -> None:
    op.drop_index("ix_execution_tokens_chain_id", table_name="execution_tokens")
    op.drop_table("execution_tokens")

    op.drop_index("ix_review_results_chain_id", table_name="review_results")
    op.drop_table("review_results")

    op.drop_index("ix_evidence_packets_chain_id", table_name="evidence_packets")
    op.drop_table("evidence_packets")

    op.drop_index("ix_incidents_agent_id", table_name="incidents")
    op.drop_table("incidents")

    op.drop_index("ix_enrollment_tokens_agent_id", table_name="enrollment_tokens")
    op.drop_index("ix_enrollment_tokens_agent_did", table_name="enrollment_tokens")
    op.drop_table("enrollment_tokens")

    op.drop_table("agents")

    op.drop_index("ix_chain_events_event_id", table_name="chain_events")
    op.drop_table("chain_events")

    op.drop_table("governance_chains")
