"""Create enrollment_records table.

Revision ID: 0002_enrollment_records
Revises: 0001_baseline
Create Date: 2026-04-14

Wave 2B declared ``EnrollmentRecordRow`` inside the repositories module
because the wave was scoped to ``gavel/db/repositories/``. Wave 3 moves
that declaration into :mod:`gavel.db.models` and adds the matching
migration. No data exists at this point — the baseline migration never
created an ``enrollment_records`` table.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "0002_enrollment_records"
down_revision: Union[str, None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "enrollment_records",
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="PENDING"),
        sa.Column("application", sa.JSON(), nullable=False),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.String(), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("violations", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("agent_id"),
    )


def downgrade() -> None:
    op.drop_table("enrollment_records")
