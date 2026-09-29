"""Repository-ingestion tables: repositories + analyses.

Revision ID: 9f3a2c1e4b5d
Revises: None (initial schema)
Create Date: 2026-09-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9f3a2c1e4b5d"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("normalized_url", sa.String(2048), nullable=False, unique=True),
        sa.Column("owner", sa.String(39), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("default_branch", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "analyses",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("repository_id", sa.String(32), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("requested_branch", sa.String(255), nullable=True),
        sa.Column("requested_commit", sa.String(64), nullable=True),
        sa.Column("resolved_branch", sa.String(255), nullable=True),
        sa.Column("branch_origin", sa.String(16), nullable=True),
        sa.Column("resolved_commit_sha", sa.String(64), nullable=True),
        sa.Column("commit_origin", sa.String(16), nullable=True),
        sa.Column("stage", sa.String(32), nullable=False, server_default="Queued"),
        sa.Column("outcome", sa.String(32), nullable=True),
        sa.Column("analyzer_version", sa.String(64), nullable=False),
        sa.Column("rule_set_version", sa.String(64), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("workspace_path", sa.String(4096), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_analyses_repository_id", "analyses", ["repository_id"])


def downgrade() -> None:
    op.drop_index("ix_analyses_repository_id", table_name="analyses")
    op.drop_table("analyses")
    op.drop_table("repositories")
