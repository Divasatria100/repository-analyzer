"""File-index tables: files + limitations.

Revision ID: 7d2b9f4a1c6e
Revises: 9f3a2c1e4b5d
Create Date: 2026-09-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7d2b9f4a1c6e"
down_revision: str | Sequence[str] | None = "9f3a2c1e4b5d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "files",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("analysis_id", sa.String(32), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("path", sa.String(4096), nullable=False),
        sa.Column("file_type", sa.String(32), nullable=False),
        sa.Column("extension", sa.String(32), nullable=False, server_default=""),
        sa.Column("size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("language", sa.String(32), nullable=True),
        sa.Column("support_status", sa.String(16), nullable=False),
        sa.Column("is_binary", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("is_generated", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("excluded", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("exclusion_reason", sa.String(1024), nullable=True),
        sa.Column("eligibility", sa.String(16), nullable=False),
        sa.Column("eligibility_reason", sa.String(1024), nullable=True),
        sa.Column("parse_result", sa.String(32), nullable=True),
        sa.Column("indexing_limitation", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("analysis_id", "path", name="uq_files_analysis_path"),
    )
    op.create_index("ix_files_analysis_id", "files", ["analysis_id"])
    op.create_table(
        "limitations",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("analysis_id", sa.String(32), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("scope_kind", sa.String(32), nullable=False),
        sa.Column("file_path", sa.String(4096), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_limitations_analysis_id", "limitations", ["analysis_id"])


def downgrade() -> None:
    op.drop_index("ix_limitations_analysis_id", table_name="limitations")
    op.drop_table("limitations")
    # Dropping the table removes its constraints on every dialect (SQLite
    # has no ALTER for constraint drops), so no explicit drop_constraint.
    op.drop_index("ix_files_analysis_id", table_name="files")
    op.drop_table("files")
