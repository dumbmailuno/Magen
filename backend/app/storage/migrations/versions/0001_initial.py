"""Initial schema: targets, scans, findings, probe_audit.

Revision ID: 0001
Revises:
Create Date: 2026-11-22
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the initial tables."""
    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host", sa.String(253), nullable=False, unique=True),
        sa.Column("is_local", sa.Boolean(), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("targets.id"), nullable=True),
        sa.Column("baseline_scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("magen_version", sa.String(32), nullable=False),
        sa.Column("commit", sa.String(40), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
    )
    op.create_table(
        "findings",
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), primary_key=True),
        sa.Column("finding_id", sa.String(20), primary_key=True),
        sa.Column("rule_id", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("status", sa.String(13), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("reviewed", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
    op.create_table(
        "probe_audit",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("method", sa.String(8), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("error", sa.String(200), nullable=True),
    )
    op.create_index("ix_probe_audit_scan_id", "probe_audit", ["scan_id"])


def downgrade() -> None:
    """Drop all tables."""
    op.drop_index("ix_probe_audit_scan_id", "probe_audit")
    op.drop_table("probe_audit")
    op.drop_index("ix_findings_rule_id", "findings")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("targets")
