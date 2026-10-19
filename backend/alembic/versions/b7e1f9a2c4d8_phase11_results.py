"""Phase 11 result aggregation tables (TASK-148–156).

Revision ID: b7e1f9a2c4d8
Revises: 3f8c2e5b9a1d
Create Date: 2026-10-14

Creates rules, findings (+ locations, module/dependency associations),
dependencies (+ relationships, advisories), architecture metrics, modules
(+ dependencies), domain states, rule evaluations, file coverages, and
analysis snapshots; extends analyses with provenance/config/status columns
and limitations with area/rule/file references. All constraints use
SQLite-compatible DDL (no ALTER .. ADD CONSTRAINT); composite rule
references on new tables are inline foreign keys.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b7e1f9a2c4d8"
down_revision: str | Sequence[str] | None = "3f8c2e5b9a1d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.create_table(
        "rules",
        sa.Column("rule_id", sa.String(64), primary_key=True),
        sa.Column("rule_set_version", sa.String(64), primary_key=True),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("default_severity", sa.String(32), nullable=True),
        sa.Column("documentation_ref", sa.String(1024), nullable=True),
        *_timestamps(),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("analysis_id", sa.String(32), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("rule_set_version", sa.String(64), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("finding_id", sa.String(64), nullable=False, server_default=""),
        sa.Column("identity_key", sa.String(64), nullable=False),
        sa.Column("subject_key", sa.String(1024), nullable=False, server_default=""),
        sa.Column("title", sa.Text(), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(32), nullable=False),
        sa.Column("location_file_id", sa.String(32), sa.ForeignKey("files.id"), nullable=True),
        sa.Column("location_path", sa.String(4096), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("end_line", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("start_column", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("end_column", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("redacted", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("recommendation", sa.Text(), nullable=False, server_default=""),
        sa.Column("impact", sa.Text(), nullable=True),
        sa.Column("severity_factors", sa.JSON(), nullable=True),
        sa.Column("confidence_factors", sa.JSON(), nullable=True),
        sa.Column("applied_thresholds", sa.JSON(), nullable=True),
        sa.Column("partial_info", sa.Boolean(), nullable=False, server_default="0"),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["rule_id", "rule_set_version"],
            ["rules.rule_id", "rules.rule_set_version"],
            name="fk_findings_rule",
        ),
        sa.UniqueConstraint("analysis_id", "identity_key", name="uq_findings_analysis_identity"),
        sa.UniqueConstraint("analysis_id", "finding_id", name="uq_findings_analysis_finding_id"),
    )
    op.create_index("ix_findings_analysis_id", "findings", ["analysis_id"])
    op.create_table(
        "finding_locations",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("finding_id", sa.String(32), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("file_id", sa.String(32), sa.ForeignKey("files.id"), nullable=True),
        sa.Column("path", sa.String(4096), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("end_line", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("start_column", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("end_column", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("primary", sa.Boolean(), nullable=False, server_default="0"),
        *_timestamps(),
    )
    op.create_index("ix_finding_locations_finding_id", "finding_locations", ["finding_id"])
    op.create_table(
        "modules",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("analysis_id", sa.String(32), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("module_id", sa.String(4096), nullable=False),
        sa.Column("file_id", sa.String(32), sa.ForeignKey("files.id"), nullable=True),
        sa.Column("partially_represented", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("layer", sa.String(64), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint("analysis_id", "module_id", name="uq_modules_analysis_module"),
    )
    op.create_index("ix_modules_analysis_id", "modules", ["analysis_id"])
    op.create_table(
        "finding_modules",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("finding_id", sa.String(32), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("module_id", sa.String(32), sa.ForeignKey("modules.id"), nullable=False),
        sa.Column("module_node_id", sa.String(4096), nullable=False, server_default=""),
        sa.Column("module_layer", sa.String(64), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint("finding_id", "module_id", name="uq_finding_modules_pair"),
    )
    op.create_index("ix_finding_modules_finding_id", "finding_modules", ["finding_id"])
    op.create_table(
        "dependencies",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("analysis_id", sa.String(32), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("ecosystem", sa.String(32), nullable=False),
        sa.Column("canonical_name", sa.String(512), nullable=False),
        sa.Column("original_name", sa.String(512), nullable=False),
        sa.Column("constraint", sa.String(1024), nullable=True),
        sa.Column("resolved_version", sa.String(256), nullable=True),
        sa.Column("manifest_file_id", sa.String(32), sa.ForeignKey("files.id"), nullable=True),
        sa.Column("source_manifest", sa.String(4096), nullable=False, server_default=""),
        sa.Column("section", sa.String(512), nullable=False, server_default=""),
        sa.Column("dependency_class", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("runtime_context", sa.String(32), nullable=False, server_default="unknown"),
        sa.Column("source_line", sa.Integer(), nullable=True),
        sa.Column("kind", sa.String(32), nullable=False, server_default="registry"),
        *_timestamps(),
    )
    op.create_index("ix_dependencies_analysis_id", "dependencies", ["analysis_id"])
    op.create_index(
        "ix_dependencies_analysis_package",
        "dependencies",
        ["analysis_id", "ecosystem", "canonical_name"],
    )
    op.create_table(
        "finding_dependencies",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("finding_id", sa.String(32), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("dependency_id", sa.String(32), sa.ForeignKey("dependencies.id"), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("finding_id", "dependency_id", name="uq_finding_dependencies_pair"),
    )
    op.create_index("ix_finding_dependencies_finding_id", "finding_dependencies", ["finding_id"])
    op.create_table(
        "dependency_relationships",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("parent_id", sa.String(32), sa.ForeignKey("dependencies.id"), nullable=False),
        sa.Column("child_id", sa.String(32), sa.ForeignKey("dependencies.id"), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("parent_id", "child_id", name="uq_dependency_relationships_pair"),
    )
    op.create_index(
        "ix_dependency_relationships_parent_id", "dependency_relationships", ["parent_id"]
    )
    op.create_index(
        "ix_dependency_relationships_child_id", "dependency_relationships", ["child_id"]
    )
    op.create_table(
        "dependency_advisories",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("dependency_id", sa.String(32), sa.ForeignKey("dependencies.id"), nullable=False),
        sa.Column("advisory_id", sa.String(256), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("affected_version", sa.String(256), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint(
            "dependency_id", "advisory_id", "source", name="uq_dependency_advisories_triple"
        ),
    )
    op.create_index(
        "ix_dependency_advisories_dependency_id", "dependency_advisories", ["dependency_id"]
    )
    op.create_table(
        "architecture_metrics",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("analysis_id", sa.String(32), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("area", sa.String(32), nullable=False),
        sa.Column("metric_name", sa.String(128), nullable=False),
        sa.Column("subject_kind", sa.String(32), nullable=False, server_default="repository"),
        sa.Column("subject_path", sa.String(4096), nullable=False, server_default=""),
        sa.Column("subject_name", sa.String(1024), nullable=False, server_default=""),
        sa.Column("value", sa.Integer(), nullable=True),
        sa.Column("availability", sa.String(16), nullable=False, server_default="available"),
        sa.Column("potentially_incomplete", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("basis", sa.Text(), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint(
            "analysis_id",
            "area",
            "metric_name",
            "subject_kind",
            "subject_path",
            "subject_name",
            name="uq_architecture_metrics_subject",
        ),
    )
    op.create_index("ix_architecture_metrics_analysis_id", "architecture_metrics", ["analysis_id"])
    op.create_table(
        "module_dependencies",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("analysis_id", sa.String(32), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("source_id", sa.String(32), sa.ForeignKey("modules.id"), nullable=False),
        sa.Column("target_id", sa.String(32), sa.ForeignKey("modules.id"), nullable=True),
        sa.Column("target_text", sa.String(4096), nullable=False, server_default=""),
        sa.Column("resolution", sa.String(32), nullable=False),
        sa.Column("file_id", sa.String(32), sa.ForeignKey("files.id"), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("column", sa.Integer(), nullable=True),
        sa.Column("conditional", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("deferred", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("locations", sa.JSON(), nullable=True),
        *_timestamps(),
    )
    op.create_index("ix_module_dependencies_analysis_id", "module_dependencies", ["analysis_id"])
    op.create_index("ix_module_dependencies_source_id", "module_dependencies", ["source_id"])
    op.create_table(
        "domain_states",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("analysis_id", sa.String(32), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("area", sa.String(32), nullable=False),
        sa.Column("state", sa.String(64), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint("analysis_id", "area", name="uq_domain_states_analysis_area"),
    )
    op.create_index("ix_domain_states_analysis_id", "domain_states", ["analysis_id"])
    op.create_table(
        "rule_evaluations",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("analysis_id", sa.String(32), sa.ForeignKey("analyses.id"), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("rule_set_version", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["rule_id", "rule_set_version"],
            ["rules.rule_id", "rules.rule_set_version"],
            name="fk_rule_evaluations_rule",
        ),
        sa.UniqueConstraint("analysis_id", "rule_id", name="uq_rule_evaluations_analysis_rule"),
    )
    op.create_index("ix_rule_evaluations_analysis_id", "rule_evaluations", ["analysis_id"])
    op.create_table(
        "file_coverages",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("file_id", sa.String(32), sa.ForeignKey("files.id"), nullable=False),
        sa.Column("scope_kind", sa.String(32), nullable=False),
        sa.Column("scope_value", sa.String(128), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint("file_id", "scope_kind", "scope_value", name="uq_file_coverages_scope"),
    )
    op.create_index("ix_file_coverages_file_id", "file_coverages", ["file_id"])
    op.create_table(
        "analysis_snapshots",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "analysis_id", sa.String(32), sa.ForeignKey("analyses.id"), nullable=False, unique=True
        ),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        *_timestamps(),
    )
    with op.batch_alter_table("analyses") as batch:
        batch.add_column(sa.Column("analysis_config", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("advisory_source", sa.String(64), nullable=True))
        batch.add_column(
            sa.Column("advisory_consulted_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(sa.Column("advisory_status", sa.String(32), nullable=True))
        batch.add_column(sa.Column("report_status", sa.String(64), nullable=True))
        batch.add_column(sa.Column("cleanup_status", sa.String(64), nullable=True))
    with op.batch_alter_table("limitations") as batch:
        batch.add_column(sa.Column("area", sa.String(32), nullable=True))
        batch.add_column(sa.Column("rule_id", sa.String(64), nullable=True))
        batch.add_column(sa.Column("rule_set_version", sa.String(64), nullable=True))
        batch.add_column(sa.Column("file_id", sa.String(32), nullable=True))
        batch.create_foreign_key("fk_limitations_file_id", "files", ["file_id"], ["id"])


def downgrade() -> None:
    with op.batch_alter_table("limitations") as batch:
        batch.drop_constraint("fk_limitations_file_id", type_="foreignkey")
        batch.drop_column("file_id")
        batch.drop_column("rule_set_version")
        batch.drop_column("rule_id")
        batch.drop_column("area")
    with op.batch_alter_table("analyses") as batch:
        batch.drop_column("cleanup_status")
        batch.drop_column("report_status")
        batch.drop_column("advisory_status")
        batch.drop_column("advisory_consulted_at")
        batch.drop_column("advisory_source")
        batch.drop_column("analysis_config")
    op.drop_table("analysis_snapshots")
    op.drop_index("ix_file_coverages_file_id", table_name="file_coverages")
    op.drop_table("file_coverages")
    op.drop_index("ix_rule_evaluations_analysis_id", table_name="rule_evaluations")
    op.drop_table("rule_evaluations")
    op.drop_index("ix_domain_states_analysis_id", table_name="domain_states")
    op.drop_table("domain_states")
    op.drop_index("ix_module_dependencies_analysis_id", table_name="module_dependencies")
    op.drop_index("ix_module_dependencies_source_id", table_name="module_dependencies")
    op.drop_table("module_dependencies")
    op.drop_index("ix_finding_modules_finding_id", table_name="finding_modules")
    op.drop_table("finding_modules")
    op.drop_index("ix_modules_analysis_id", table_name="modules")
    op.drop_table("modules")
    op.drop_index("ix_architecture_metrics_analysis_id", table_name="architecture_metrics")
    op.drop_table("architecture_metrics")
    op.drop_index("ix_dependency_advisories_dependency_id", table_name="dependency_advisories")
    op.drop_table("dependency_advisories")
    op.drop_index("ix_finding_dependencies_finding_id", table_name="finding_dependencies")
    op.drop_table("finding_dependencies")
    op.drop_index("ix_dependency_relationships_child_id", table_name="dependency_relationships")
    op.drop_index("ix_dependency_relationships_parent_id", table_name="dependency_relationships")
    op.drop_table("dependency_relationships")
    op.drop_index("ix_dependencies_analysis_package", table_name="dependencies")
    op.drop_index("ix_dependencies_analysis_id", table_name="dependencies")
    op.drop_table("dependencies")
    op.drop_index("ix_finding_locations_finding_id", table_name="finding_locations")
    op.drop_table("finding_locations")
    op.drop_index("ix_findings_analysis_id", table_name="findings")
    op.drop_table("findings")
    op.drop_table("rules")
