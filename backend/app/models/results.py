"""Result aggregation persistence entities (docs/12 §4.4–4.9).

Analysis-owned result records plus the reusable Rule definition and the
sealing AnalysisSnapshot. Every analysis-scoped row belongs to exactly one
analysis; findings reference rules by (rule_id, rule_set_version); no
attribute holds secrets or scores.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

#: Canonical analysis areas (docs/10 §7.2, docs/13 §6.3).
AREAS = frozenset({"security", "dependency", "architecture", "code_structure"})

#: Canonical domain states (docs/10 §7.2, docs/13 §6.3, FR-100).
DOMAIN_STATES = frozenset(
    {
        "No findings detected",
        "Analysis not performed",
        "Analysis failed",
        "Analysis incomplete",
        "Analysis unavailable",
    }
)

#: Canonical rule evaluation states (docs/10 §7.2, docs/13 §6.4).
RULE_EVAL_STATES = frozenset({"Evaluated", "Partially evaluated", "Not evaluated", "Failed"})

#: Canonical file coverage states (docs/10 §7.2, docs/13 §13).
FILE_COVERAGE_STATES = frozenset({"Fully analyzed", "Partially analyzed", "Not analyzed", "Failed"})

#: Canonical limitation scope kinds (docs/13 §6.5) plus the two
#: pre-existing indexing scopes, which remain valid.
LIMITATION_SCOPES = frozenset(
    {
        "index",
        "file",
        "analysis",
        "area",
        "rule",
        "dependency manifest",
        "unretrieved content",
        "advisory lookup",
        "resource limit",
    }
)

#: Metric availability (docs/13 §10.1, ARCH-REQ-027).
METRIC_AVAILABILITY = frozenset({"available", "unavailable"})

#: Module dependency resolutions (docs/12 §4.7.1, ARCH-REQ-015).
DEPENDENCY_RESOLUTIONS = frozenset({"internal", "external", "unresolved"})

#: Dependency classifications (docs/12 §4.6, FR-048/049).
DEPENDENCY_CLASSES = frozenset({"direct", "transitive", "unknown"})

#: Terminal outcomes shared with the ingestion lifecycle (docs/10 §7.2).
TERMINAL_OUTCOMES = frozenset({"Completed", "Completed with limitations", "Failed"})


def _new_id() -> str:
    return uuid.uuid4().hex


class Rule(Base, TimestampMixin):
    """Reusable rule definition, identified by ID within a rule-set version.

    Rows are immutable once written: definitions of a published rule-set
    version are never changed by later analyses (docs/12 §4.5, §7.2).
    """

    __tablename__ = "rules"

    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_set_version: Mapped[str] = mapped_column(String(64), primary_key=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    default_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    documentation_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    findings: Mapped[list[Finding]] = relationship(back_populates="rule")


class Finding(Base, TimestampMixin):
    """One persisted analyzer finding (docs/12 §4.4, §9).

    Evidence is stored already redacted and bounded; severity/confidence are
    stored exactly as assigned. ``finding_id`` is assigned deterministically
    at persist time when the analyzer left it empty.
    """

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_set_version: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    identity_key: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_key: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    location_file_id: Mapped[str | None] = mapped_column(ForeignKey("files.id"), nullable=True)
    location_path: Mapped[str] = mapped_column(String(4096), nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    start_column: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    end_column: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    redacted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity_factors: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    confidence_factors: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    applied_thresholds: Mapped[list[list[object]] | None] = mapped_column(JSON, nullable=True)
    partial_info: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["rule_id", "rule_set_version"],
            ["rules.rule_id", "rules.rule_set_version"],
            name="fk_findings_rule",
        ),
        # One record per stable identity within an analysis (docs/13 §8.1).
        UniqueConstraint("analysis_id", "identity_key", name="uq_findings_analysis_identity"),
        UniqueConstraint("analysis_id", "finding_id", name="uq_findings_analysis_finding_id"),
    )

    rule: Mapped[Rule] = relationship(back_populates="findings")
    locations: Mapped[list[FindingLocation]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    modules: Mapped[list[FindingModule]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    dependencies: Mapped[list[FindingDependency]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class FindingLocation(Base, TimestampMixin):
    """One file location of a finding; exactly one is primary (docs/12 §4.4.1)."""

    __tablename__ = "finding_locations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    file_id: Mapped[str | None] = mapped_column(ForeignKey("files.id"), nullable=True)
    path: Mapped[str] = mapped_column(String(4096), nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    start_column: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    end_column: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    finding: Mapped[Finding] = relationship(back_populates="locations")


class FindingModule(Base, TimestampMixin):
    """Association between a finding and a module it concerns.

    The node id and layer label are snapshotted on the row so the
    canonical subject stays stable even if module rows evolve.
    """

    __tablename__ = "finding_modules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    module_id: Mapped[str] = mapped_column(ForeignKey("modules.id"), nullable=False)
    module_node_id: Mapped[str] = mapped_column(String(4096), nullable=False, default="")
    module_layer: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (UniqueConstraint("finding_id", "module_id", name="uq_finding_modules_pair"),)

    finding: Mapped[Finding] = relationship(back_populates="modules")


class FindingDependency(Base, TimestampMixin):
    """Association between a finding and a dependency occurrence it concerns."""

    __tablename__ = "finding_dependencies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    dependency_id: Mapped[str] = mapped_column(ForeignKey("dependencies.id"), nullable=False)

    __table_args__ = (
        UniqueConstraint("finding_id", "dependency_id", name="uq_finding_dependencies_pair"),
    )

    finding: Mapped[Finding] = relationship(back_populates="dependencies")


class Dependency(Base, TimestampMixin):
    """One dependency occurrence in one analysis (docs/12 §4.6)."""

    __tablename__ = "dependencies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False)
    canonical_name: Mapped[str] = mapped_column(String(512), nullable=False)
    original_name: Mapped[str] = mapped_column(String(512), nullable=False)
    constraint: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    resolved_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    manifest_file_id: Mapped[str | None] = mapped_column(ForeignKey("files.id"), nullable=True)
    source_manifest: Mapped[str] = mapped_column(String(4096), nullable=False, default="")
    section: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    dependency_class: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    runtime_context: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    source_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="registry")

    relationships: Mapped[list[DependencyRelationship]] = relationship(
        back_populates="parent",
        cascade="all, delete-orphan",
        foreign_keys="DependencyRelationship.parent_id",
    )
    advisories: Mapped[list[DependencyAdvisory]] = relationship(
        back_populates="dependency", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Occurrences repeat by design (docs/12 §4.6); lookup, not uniqueness.
        Index("ix_dependencies_analysis_package", "analysis_id", "ecosystem", "canonical_name"),
    )


class DependencyRelationship(Base, TimestampMixin):
    """Introduced-by edge between two occurrences of one analysis (§4.6.1)."""

    __tablename__ = "dependency_relationships"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    parent_id: Mapped[str] = mapped_column(
        ForeignKey("dependencies.id"), nullable=False, index=True
    )
    child_id: Mapped[str] = mapped_column(ForeignKey("dependencies.id"), nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("parent_id", "child_id", name="uq_dependency_relationships_pair"),
    )

    parent: Mapped[Dependency] = relationship(
        back_populates="relationships", foreign_keys=[parent_id]
    )


class DependencyAdvisory(Base, TimestampMixin):
    """Bounded advisory association: identifier + source only (§4.6.1)."""

    __tablename__ = "dependency_advisories"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    dependency_id: Mapped[str] = mapped_column(
        ForeignKey("dependencies.id"), nullable=False, index=True
    )
    advisory_id: Mapped[str] = mapped_column(String(256), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    affected_version: Mapped[str | None] = mapped_column(String(256), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "dependency_id", "advisory_id", "source", name="uq_dependency_advisories_triple"
        ),
    )

    dependency: Mapped[Dependency] = relationship(back_populates="advisories")


class ArchitectureMetric(Base, TimestampMixin):
    """One measured value with availability semantics (docs/12 §4.7)."""

    __tablename__ = "architecture_metrics"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    area: Mapped[str] = mapped_column(String(32), nullable=False)
    metric_name: Mapped[str] = mapped_column(String(128), nullable=False)
    subject_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="repository")
    subject_path: Mapped[str] = mapped_column(String(4096), nullable=False, default="")
    subject_name: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    value: Mapped[int | None] = mapped_column(Integer, nullable=True)
    availability: Mapped[str] = mapped_column(String(16), nullable=False, default="available")
    potentially_incomplete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    basis: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "analysis_id",
            "area",
            "metric_name",
            "subject_kind",
            "subject_path",
            "subject_name",
            name="uq_architecture_metrics_subject",
        ),
    )


class Module(Base, TimestampMixin):
    """One architecture graph node in one analysis (docs/12 §4.7.1)."""

    __tablename__ = "modules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    module_id: Mapped[str] = mapped_column(String(4096), nullable=False)
    file_id: Mapped[str | None] = mapped_column(ForeignKey("files.id"), nullable=True)
    partially_represented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    layer: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("analysis_id", "module_id", name="uq_modules_analysis_module"),
    )


class ModuleDependency(Base, TimestampMixin):
    """One directed module reference in one analysis (docs/12 §4.7.1)."""

    __tablename__ = "module_dependencies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("modules.id"), nullable=False, index=True)
    target_id: Mapped[str | None] = mapped_column(ForeignKey("modules.id"), nullable=True)
    target_text: Mapped[str] = mapped_column(String(4096), nullable=False, default="")
    resolution: Mapped[str] = mapped_column(String(32), nullable=False)
    file_id: Mapped[str | None] = mapped_column(ForeignKey("files.id"), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    column: Mapped[int | None] = mapped_column(Integer, nullable=True)
    conditional: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deferred: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    locations: Mapped[list[list[object]] | None] = mapped_column(JSON, nullable=True)


class DomainState(Base, TimestampMixin):
    """One domain state per analysis and area (docs/12 §4.9)."""

    __tablename__ = "domain_states"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    area: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("analysis_id", "area", name="uq_domain_states_analysis_area"),
    )


class RuleEvaluation(Base, TimestampMixin):
    """One rule evaluation per analysis and rule (docs/12 §4.9)."""

    __tablename__ = "rule_evaluations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_set_version: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["rule_id", "rule_set_version"],
            ["rules.rule_id", "rules.rule_set_version"],
            name="fk_rule_evaluations_rule",
        ),
        UniqueConstraint("analysis_id", "rule_id", name="uq_rule_evaluations_analysis_rule"),
    )


class FileCoverage(Base, TimestampMixin):
    """File analysis state per scope where it differs (docs/12 §4.9)."""

    __tablename__ = "file_coverages"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id"), nullable=False, index=True)
    scope_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    scope_value: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("file_id", "scope_kind", "scope_value", name="uq_file_coverages_scope"),
    )


class AnalysisSnapshot(Base, TimestampMixin):
    """Sealed result designation for one completed analysis (docs/12 §4.8)."""

    __tablename__ = "analysis_snapshots"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), nullable=False, unique=True)
    sealed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)


def utcnow() -> datetime:
    """Timezone-aware now for seal timestamps."""
    return datetime.now(UTC)
