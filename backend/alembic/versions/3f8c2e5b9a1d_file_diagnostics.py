"""File diagnostics column for persisted parse results.

Revision ID: 3f8c2e5b9a1d
Revises: 7d2b9f4a1c6e
Create Date: 2026-09-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "3f8c2e5b9a1d"
down_revision: str | Sequence[str] | None = "7d2b9f4a1c6e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("files", sa.Column("diagnostics", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("files", "diagnostics")
