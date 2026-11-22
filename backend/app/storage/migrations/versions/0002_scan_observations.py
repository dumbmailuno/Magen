"""Store recorded runtime observations on scans (for correlation and replay).

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-22
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add scans.observations (redacted JSON from app.runtime.recording)."""
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("observations", sa.Text(), nullable=True))


def downgrade() -> None:
    """Drop scans.observations."""
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("observations")
