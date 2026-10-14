"""Persistence gateway for result aggregation output (docs/12 §4.4–4.9).

Persists analyzer findings with their subject associations, the
architecture graph, dependency occurrences, metrics, domain states, rule
evaluations, file coverages, and limitations; seals completed snapshots;
and loads snapshots back for canonical serialization and comparison.

Callers own the transaction via ``session_scope`` — helpers flush; failures
roll back safely there. Every writer refuses a sealed snapshot, and each
entity kind is persisted at most once per analysis (fail fast instead of
double-writing). Vocabulary is validated here so invalid states never reach
the database silently.

Analyzer ``subject_key`` strings are this repository's own analyzer outputs
(version-pinned). Association parsing is strict ``prefix:payload`` matching
with skip-on-mismatch only where the contract allows absence (module and
dependency links for unknown future rules); locations, thresholds, factors,
and evidence always come from stored columns, never from parsing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.analyzers.findings import Confidence, Finding, Limitation, Severity
from app.models.indexing import File
from app.models.indexing import Limitation as LimitationRow
from app.models.repository import Analysis, Repository, utcnow
from app.models.results import (
    AREAS,
    LIMITATION_SCOPES,
    METRIC_AVAILABILITY,
    AnalysisSnapshot,
    ArchitectureMetric,
    Dependency,
    DependencyAdvisory,
    DependencyRelationship,
    DomainState,
    FileCoverage,
    FindingDependency,
    FindingLocation,
    FindingModule,
    Module,
    ModuleDependency,
    Rule,
    RuleEvaluation,
)
from app.models.results import (
    Finding as FindingRow,
)
from app.results.aggregation import (
    DOMAIN_STATES,
    FILE_COVERAGE_STATES,
    RULE_EVAL_STATES,
)
from app.results.canonical import (
    METRIC_DEFINITIONS,
    SnapshotData,
    build_canonical_result,
    snapshot_view_from_data,
)
from app.results.comparison import ComparisonResult, compare_snapshots


class SealedSnapshotError(ValueError):
    """Raised when a write targets an analysis with a sealed snapshot."""


class IncompleteSnapshotError(ValueError):
    """Raised when sealing or reading finds a snapshot below the contract."""


#: Completed outcomes that may be sealed (docs/13 §3.3, §6.6).
SEALABLE_OUTCOMES = frozenset({"Completed", "Completed with limitations"})

#: Stored advisory consultation statuses (docs/13 §4.3, lowercase).
ADVISORY_STATUSES = frozenset({"succeeded", "partly succeeded", "unavailable"})

#: Module dependency resolutions (docs/12 §4.7.1, ARCH-REQ-015).
MODULE_RESOLUTIONS = frozenset({"internal", "external", "unresolved"})


@dataclass(frozen=True)
class RuleDefinition:
    """One rule of a rule-set version for the immutable rule registry."""

    rule_id: str
    name: str
    category: str
    description: str = ""
    default_severity: str | None = None
    documentation_ref: str | None = None


@dataclass(frozen=True)
class MetricInput:
    """One measured value with availability semantics (docs/12 §4.7)."""

    area: str
    metric_name: str
    subject_path: str = ""
    subject_name: str = ""
    subject_kind: str = "repository"
    value: int | None = None
    availability: str = "available"
    potentially_incomplete: bool = False
    basis: str | None = None


@dataclass(frozen=True)
class ModuleDepInput:
    """One directed module reference (docs/12 §4.7.1)."""

    target: str | None
    target_text: str
    resolution: str
    file_path: str | None = None
    line: int | None = None
    column: int | None = None
    conditional: bool = False
    deferred: bool = False
    locations: tuple[tuple[str, int | None, int | None], ...] = ()


@dataclass(frozen=True)
class ModuleInput:
    """One architecture graph node with its outgoing references."""

    module_id: str
    file_path: str | None = None
    partially_represented: bool = False
    layer: str | None = None
    dependencies: tuple[ModuleDepInput, ...] = ()


@dataclass(frozen=True)
class DependencyAdvisoryInput:
    """One advisory association: identifier plus source only."""

    advisory_id: str
    source: str
    affected_version: str | None = None


@dataclass(frozen=True)
class DependencyKey:
    """Stable lookup key of one dependency occurrence."""

    ecosystem: str
    canonical_name: str
    resolved_version: str | None
    source_manifest: str
    source_line: int | None


@dataclass(frozen=True)
class DependencyInput:
    """One dependency occurrence with its edges and advisories."""

    ecosystem: str
    canonical_name: str
    original_name: str
    source_manifest: str
    section: str = ""
    constraint: str | None = None
    resolved_version: str | None = None
    dependency_class: str = "unknown"
    runtime_context: str = "unknown"
    source_line: int | None = None
    kind: str = "registry"
    introduced_by: tuple[DependencyKey, ...] = ()
    advisories: tuple[DependencyAdvisoryInput, ...] = ()

    def key(self) -> DependencyKey:
        """Lookup key of this occurrence."""
        return DependencyKey(
            ecosystem=self.ecosystem,
            canonical_name=self.canonical_name,
            resolved_version=self.resolved_version,
            source_manifest=self.source_manifest,
            source_line=self.source_line,
        )


@dataclass(frozen=True)
class DomainStateInput:
    """One domain state with its reason (docs/12 §4.9)."""

    area: str
    state: str | None
    reason: str | None = None


@dataclass(frozen=True)
class RuleEvaluationInput:
    """One rule evaluation state (docs/12 §4.9)."""

    rule_id: str
    state: str
    reason: str | None = None


@dataclass(frozen=True)
class FileCoverageInput:
    """One file coverage row for a non-Fully scope (docs/12 §4.9)."""

    path: str
    scope_kind: str
    scope_value: str
    state: str
    reason: str | None = None


def _require_unsealed(session: Session, analysis_id: str) -> None:
    """Reject writes to an analysis with a sealed snapshot."""
    sealed = session.scalar(
        select(AnalysisSnapshot.id).where(AnalysisSnapshot.analysis_id == analysis_id)
    )
    if sealed is not None:
        raise SealedSnapshotError(f"Analysis {analysis_id!r} already has a sealed snapshot.")


def _files_by_path(session: Session, analysis_id: str) -> dict[str, File]:
    """Index an analysis' file rows by path (fail fast on duplicates)."""
    rows = session.scalars(
        select(File).where(File.analysis_id == analysis_id).order_by(File.path)
    ).all()
    index: dict[str, File] = {}
    for row in rows:
        if row.path in index:
            raise IncompleteSnapshotError(f"Duplicate file path in index: {row.path!r}.")
        index[row.path] = row
    return index


def _kind_present(session: Session, entity: Any, analysis_id: str) -> bool:
    """Whether any row of an analysis-scoped entity exists already."""
    return session.scalar(select(entity.id).where(entity.analysis_id == analysis_id)) is not None


def ensure_rules(
    session: Session, rule_set_version: str, rules: list[RuleDefinition]
) -> dict[str, Rule]:
    """Get or create the immutable rule rows of one rule-set version.

    Existing rows are never modified: content drift under a published
    version raises instead of overwriting (docs/12 §4.5, §7.2).
    """
    ordered = sorted(rules, key=lambda item: item.rule_id)
    if [item.rule_id for item in ordered] != sorted({item.rule_id for item in ordered}):
        raise ValueError("Duplicate rule ids in rule definitions.")
    resolved: dict[str, Rule] = {}
    for definition in ordered:
        if definition.category not in AREAS:
            raise ValueError(f"Unknown rule category for {definition.rule_id!r}.")
        row = session.get(Rule, (definition.rule_id, rule_set_version))
        if row is None:
            row = Rule(
                rule_id=definition.rule_id,
                rule_set_version=rule_set_version,
                category=definition.category,
                name=definition.name,
                description=definition.description,
                default_severity=definition.default_severity,
                documentation_ref=definition.documentation_ref,
            )
            session.add(row)
            session.flush()
        elif (
            row.category != definition.category
            or row.name != definition.name
            or row.description != definition.description
            or row.default_severity != definition.default_severity
            or row.documentation_ref != definition.documentation_ref
        ):
            raise ValueError(
                f"Rule {definition.rule_id!r} of version {rule_set_version!r} is immutable."
            )
        resolved[definition.rule_id] = row
    return resolved


def record_results_context(
    session: Session,
    analysis: Analysis,
    *,
    configuration: dict[str, object],
    advisory_source: str | None = None,
    advisory_consulted_at: datetime | None = None,
    advisory_status: str | None = None,
) -> Analysis:
    """Record the effective configuration snapshot and advisory reference.

    The configuration is stored as the values used, never as a reference
    to mutable settings (docs/13 §4.2). Only completed analyses carry
    results context, and a sealed snapshot rejects the write.
    """
    _require_unsealed(session, analysis.id)
    if analysis.outcome is not None:
        raise ValueError("Terminal analysis results context must not change.")
    if not configuration:
        raise ValueError("Results configuration snapshot must not be empty.")
    if advisory_status is not None and advisory_status not in ADVISORY_STATUSES:
        raise ValueError(f"Unknown advisory status: {advisory_status!r}.")
    if advisory_source is None and (
        advisory_consulted_at is not None or advisory_status is not None
    ):
        raise ValueError("Advisory details require an advisory source.")
    analysis.analysis_config = dict(configuration)
    analysis.advisory_source = advisory_source
    analysis.advisory_consulted_at = advisory_consulted_at
    analysis.advisory_status = advisory_status
    session.flush()
    return analysis


def persist_modules(
    session: Session, analysis_id: str, modules: list[ModuleInput]
) -> dict[str, Module]:
    """Persist architecture graph nodes plus their references (docs/12 §4.7.1)."""
    _require_unsealed(session, analysis_id)
    if _kind_present(session, Module, analysis_id):
        raise ValueError(f"Modules for analysis {analysis_id!r} were already persisted.")
    node_ids = sorted(module.module_id for module in modules)
    if len(set(node_ids)) != len(node_ids):
        raise ValueError("Duplicate module ids in module inputs.")
    files = _files_by_path(session, analysis_id)
    rows: dict[str, Module] = {}
    for module in sorted(modules, key=lambda item: item.module_id):
        file_id: str | None = None
        if module.file_path is not None:
            if module.file_path not in files:
                raise ValueError(f"Module {module.module_id!r} has an unknown file.")
            file_id = files[module.file_path].id
        row = Module(
            analysis_id=analysis_id,
            module_id=module.module_id,
            file_id=file_id,
            partially_represented=module.partially_represented,
            layer=module.layer,
        )
        session.add(row)
        rows[module.module_id] = row
    session.flush()
    for module in sorted(modules, key=lambda item: item.module_id):
        source = rows[module.module_id]
        for dependency in module.dependencies:
            _persist_module_dependency(session, analysis_id, source, dependency, rows, files)
    session.flush()
    return rows


def _persist_module_dependency(
    session: Session,
    analysis_id: str,
    source: Module,
    dependency: ModuleDepInput,
    rows: dict[str, Module],
    files: dict[str, File],
) -> None:
    """Persist one directed module reference with resolution semantics."""
    if dependency.resolution not in MODULE_RESOLUTIONS:
        raise ValueError(f"Unknown module dependency resolution: {dependency.resolution!r}.")
    target_id: str | None = None
    if dependency.resolution == "internal":
        if dependency.target is None or dependency.target not in rows:
            raise ValueError(
                f"Internal reference {dependency.target_text!r} has no known target module."
            )
        target_id = rows[dependency.target].id
    elif dependency.target is not None:
        raise ValueError(
            f"Non-internal reference {dependency.target_text!r} must not name a target module."
        )
    file_id: str | None = None
    if dependency.file_path is not None:
        if dependency.file_path not in files:
            raise ValueError(f"Module reference {dependency.target_text!r} has an unknown file.")
        file_id = files[dependency.file_path].id
    session.add(
        ModuleDependency(
            analysis_id=analysis_id,
            source_id=source.id,
            target_id=target_id,
            target_text=dependency.target_text,
            resolution=dependency.resolution,
            file_id=file_id,
            line=dependency.line,
            column=dependency.column,
            conditional=dependency.conditional,
            deferred=dependency.deferred,
            locations=[list(site) for site in dependency.locations] or None,
        )
    )


def persist_dependencies(
    session: Session, analysis_id: str, dependencies: list[DependencyInput]
) -> dict[DependencyKey, Dependency]:
    """Persist dependency occurrences with edges and advisories (§4.6)."""
    _require_unsealed(session, analysis_id)
    if _kind_present(session, Dependency, analysis_id):
        raise ValueError(f"Dependencies for analysis {analysis_id!r} were already persisted.")
    files = _files_by_path(session, analysis_id)
    rows: dict[DependencyKey, Dependency] = {}
    for item in sorted(
        dependencies,
        key=lambda entry: (
            entry.ecosystem,
            entry.canonical_name,
            entry.resolved_version or "",
            entry.source_manifest,
            entry.source_line or 0,
        ),
    ):
        if item.source_manifest not in files:
            raise ValueError(f"Dependency {item.canonical_name!r} has an unknown manifest.")
        row = Dependency(
            analysis_id=analysis_id,
            ecosystem=item.ecosystem,
            canonical_name=item.canonical_name,
            original_name=item.original_name,
            constraint=item.constraint,
            resolved_version=item.resolved_version,
            manifest_file_id=files[item.source_manifest].id,
            source_manifest=item.source_manifest,
            section=item.section,
            dependency_class=item.dependency_class,
            runtime_context=item.runtime_context,
            source_line=item.source_line,
            kind=item.kind,
        )
        session.add(row)
        session.flush()
        for advisory in sorted(
            item.advisories, key=lambda entry: (entry.source, entry.advisory_id)
        ):
            session.add(
                DependencyAdvisory(
                    dependency_id=row.id,
                    advisory_id=advisory.advisory_id,
                    source=advisory.source,
                    affected_version=advisory.affected_version,
                )
            )
        key = item.key()
        if key in rows:
            raise ValueError(f"Duplicate dependency occurrence: {key!r}.")
        rows[key] = row
    pairs: set[tuple[str, str]] = set()
    for item in dependencies:
        child_id = rows[item.key()].id
        for parent in item.introduced_by:
            if parent not in rows:
                raise ValueError(
                    f"Dependency {item.canonical_name!r} has an unknown parent: {parent!r}."
                )
            pairs.add((rows[parent].id, child_id))
    for parent_id, child_id in sorted(pairs):
        session.add(DependencyRelationship(parent_id=parent_id, child_id=child_id))
    session.flush()
    return rows


def persist_metrics(session: Session, analysis_id: str, metrics: list[MetricInput]) -> None:
    """Persist measured values with availability semantics (docs/12 §4.7)."""
    _require_unsealed(session, analysis_id)
    if _kind_present(session, ArchitectureMetric, analysis_id):
        raise ValueError(f"Metrics for analysis {analysis_id!r} were already persisted.")
    files = _files_by_path(session, analysis_id)
    modules = {
        row.module_id
        for row in session.scalars(select(Module).where(Module.analysis_id == analysis_id)).all()
    }
    for metric in sorted(
        metrics,
        key=lambda item: (item.area, item.metric_name, item.subject_path, item.subject_name),
    ):
        if metric.area not in AREAS:
            raise ValueError(f"Unknown metric area: {metric.area!r}.")
        if metric.metric_name not in METRIC_DEFINITIONS:
            raise ValueError(f"Unknown metric name: {metric.metric_name!r}.")
        if metric.availability not in METRIC_AVAILABILITY:
            raise ValueError(f"Unknown metric availability: {metric.availability!r}.")
        if (metric.value is None) != (metric.availability == "unavailable"):
            raise ValueError(f"Metric {metric.metric_name!r} availability contradicts its value.")
        if metric.subject_path and metric.subject_path not in files:
            raise ValueError(f"Metric {metric.metric_name!r} has an unknown subject file.")
        if (
            metric.area == "architecture"
            and not metric.subject_name
            and metric.subject_path
            and metric.subject_path not in modules
        ):
            raise ValueError(f"Module metric {metric.metric_name!r} has an unknown module.")
        session.add(
            ArchitectureMetric(
                analysis_id=analysis_id,
                area=metric.area,
                metric_name=metric.metric_name,
                subject_kind=metric.subject_kind,
                subject_path=metric.subject_path,
                subject_name=metric.subject_name,
                value=metric.value,
                availability=metric.availability,
                potentially_incomplete=metric.potentially_incomplete,
                basis=metric.basis,
            )
        )
    session.flush()


def persist_findings(
    session: Session,
    analysis: Analysis,
    rules: dict[str, Rule],
    findings: list[Finding],
) -> list[FindingRow]:
    """Persist findings with locations and subject associations (§4.4).

    ``finding_id`` values left empty by analyzers are assigned
    deterministically (``F-0001`` …) over the sorted finding set, so
    equivalent inputs yield equivalent rows. Module and dependency links
    come from strict subject parsing; unknown future subjects keep the
    finding but add no links (never fail the persist).
    """
    _require_unsealed(session, analysis.id)
    if _kind_present(session, FindingRow, analysis.id):
        raise ValueError(f"Findings for analysis {analysis.id!r} were already persisted.")
    files = _files_by_path(session, analysis.id)
    modules = {
        row.module_id: row
        for row in session.scalars(select(Module).where(Module.analysis_id == analysis.id)).all()
    }
    occurrences = session.scalars(
        select(Dependency).where(Dependency.analysis_id == analysis.id)
    ).all()
    ordered = sorted(
        findings,
        key=lambda item: (
            item.rule_id,
            item.location.file_path,
            item.location.start_line,
            item.identity_key,
        ),
    )
    identities = [finding.identity_key for finding in ordered]
    if len(set(identities)) != len(identities):
        raise ValueError("Duplicate finding identities in findings batch.")
    rows: list[FindingRow] = []
    for position, finding in enumerate(ordered, start=1):
        rows.append(
            _persist_finding(
                session, analysis, rules, files, modules, list(occurrences), finding, position
            )
        )
    session.flush()
    return rows


def _persist_finding(
    session: Session,
    analysis: Analysis,
    rules: dict[str, Rule],
    files: dict[str, File],
    modules: dict[str, Module],
    occurrences: list[Dependency],
    finding: Finding,
    position: int,
) -> FindingRow:
    """Persist one finding row with its location and associations."""
    rule = rules.get(finding.rule_id)
    if rule is None:
        raise ValueError(f"Finding references an unknown rule: {finding.rule_id!r}.")
    if rule.rule_set_version != analysis.rule_set_version:
        raise ValueError(f"Finding rule version mismatch: {finding.rule_id!r}.")
    if finding.category != rule.category:
        raise ValueError(f"Finding category mismatch for rule {finding.rule_id!r}.")
    if finding.severity not in set(Severity):
        raise ValueError(f"Unknown severity: {finding.severity!r}.")
    if finding.confidence not in set(Confidence):
        raise ValueError(f"Unknown confidence: {finding.confidence!r}.")
    if finding.location.file_path not in files:
        raise ValueError(f"Finding {finding.rule_id!r} has an unknown location file.")
    evidence_payload = finding.evidence.to_dict() if finding.evidence is not None else None
    if finding.rule_id == "DEP-KNOWN-VULNERABILITY" and finding.subject_key:
        evidence_payload = _with_advisory_evidence(analysis, finding, evidence_payload or {})
    row = FindingRow(
        analysis_id=analysis.id,
        rule_id=finding.rule_id,
        rule_set_version=analysis.rule_set_version,
        category=finding.category,
        finding_id=finding.finding_id or f"F-{position:04d}",
        identity_key=finding.identity_key,
        subject_key=finding.subject_key,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        location_file_id=files[finding.location.file_path].id,
        location_path=finding.location.file_path,
        start_line=finding.location.start_line,
        end_line=finding.location.end_line,
        start_column=finding.location.start_column,
        end_column=finding.location.end_column,
        evidence=evidence_payload,
        redacted=bool(finding.evidence is not None and finding.evidence.redacted),
        recommendation=finding.recommendation,
        impact=finding.impact,
        severity_factors=list(finding.severity_factors),
        confidence_factors=list(finding.confidence_factors),
        applied_thresholds=[[name, value] for name, value in sorted(finding.applied_thresholds)]
        or None,
        partial_info=False,
    )
    session.add(row)
    session.flush()
    session.add(
        FindingLocation(
            finding_id=row.id,
            file_id=files[finding.location.file_path].id,
            path=finding.location.file_path,
            start_line=finding.location.start_line,
            end_line=finding.location.end_line,
            start_column=finding.location.start_column,
            end_column=finding.location.end_column,
            primary=True,
        )
    )
    for node_id in _arch_module_nodes(finding):
        module = modules.get(node_id)
        if module is None:
            raise ValueError(
                f"Finding {finding.rule_id!r} references an unknown module: {node_id!r}."
            )
        session.add(
            FindingModule(
                finding_id=row.id,
                module_id=module.id,
                module_node_id=module.module_id,
                module_layer=module.layer,
            )
        )
    for occurrence in _dependency_occurrences(finding, occurrences):
        session.add(FindingDependency(finding_id=row.id, dependency_id=occurrence.id))
    return row


def _with_advisory_evidence(
    analysis: Analysis, finding: Finding, payload: dict[str, object]
) -> dict[str, object]:
    """Attach the advisory association to a known-vulnerability finding.

    The advisory identifier comes from the strict subject; the source is
    the consulted advisory source recorded on the analysis.
    """
    parsed = _parse_dep_subject(finding.subject_key)
    if parsed is None or parsed[0] != "known":
        raise ValueError(
            f"Known-vulnerability finding has an unparseable subject: {finding.rule_id!r}."
        )
    _kind, _ecosystem, _package, _version, advisory_id = parsed
    if analysis.advisory_source is None:
        raise ValueError("Known-vulnerability findings require a recorded advisory source.")
    enriched = dict(payload)
    enriched["advisories"] = [{"advisory_id": advisory_id, "source": analysis.advisory_source}]
    return enriched


def _arch_module_nodes(finding: Finding) -> list[str]:
    """Module node ids from a strict architecture subject, else empty."""
    subject = finding.subject_key
    rule_id = finding.rule_id
    if rule_id in ("ARCH-HIGH-FAN-OUT", "ARCH-HIGH-FAN-IN", "ARCH-HIGH-COUPLING"):
        prefix, _, path = subject.partition(":")
        if (
            prefix in ("fan-out", "fan-in", "coupling")
            and path
            and path == finding.location.file_path
        ):
            return [path]
        return []
    if rule_id == "ARCH-CIRCULAR-DEPENDENCY":
        if subject.startswith("cycle:self:"):
            path = subject[len("cycle:self:") :]
            return [path] if path else []
        if subject.startswith("cycle:"):
            members = [member for member in subject[len("cycle:") :].split(",") if member]
            return members
        return []
    if rule_id == "ARCH-LARGE-MODULE":
        prefix, _, path = subject.partition(":")
        if prefix == "large-module" and path and path == finding.location.file_path:
            return [path]
        return []
    if rule_id in ("ARCH-LARGE-CLASS", "ARCH-LARGE-FUNCTION"):
        parts = subject.split(":", 2)
        if (
            len(parts) == 3
            and parts[0] in ("large-class", "large-function")
            and parts[1] == finding.location.file_path
            and parts[2].strip()
        ):
            return [parts[1]]
        return []
    if rule_id == "ARCH-LAYER-VIOLATION":
        head, _, tail = subject.partition(":")
        if head == "layer" and ">" in tail:
            source, _, target = tail.partition(">")
            if source and target:
                return [source, target]
        return []
    if rule_id == "ARCH-RESPONSIBILITY":
        prefix, _, path = subject.partition(":")
        if prefix == "responsibility" and path and path == finding.location.file_path:
            return [path]
        return []
    return []


def _parse_dep_subject(subject: str) -> tuple[object, ...] | None:
    """Strict dependency subject parsing, or None when not recognized."""
    if subject.count(":") < 2:
        return None
    ecosystem, _, rest = subject.partition(":")
    if not ecosystem or not rest:
        return None
    if rest.endswith(":unused-candidate"):
        name = rest[: -len(":unused-candidate")]
        if name and ":" not in name:
            return ("unused", ecosystem, name)
        return None
    head, _, tail = rest.partition(":")
    if head == "count":
        return ("count", ecosystem, tail) if tail else None
    if ":" not in tail:
        name, _, versions_text = rest.partition(":")
        versions = tuple(item for item in versions_text.split(",") if item)
        if name and ":" not in name and versions:
            return ("group", ecosystem, name, versions)
        return None
    name = head
    advisory = tail.rsplit(":", 1)[-1]
    version = tail[: -len(advisory) - 1] if advisory else ""
    if name and ":" not in name and version and advisory and ":" not in advisory:
        return ("known", ecosystem, name, version, advisory)
    return None


def _dependency_occurrences(finding: Finding, occurrences: list[Dependency]) -> list[Dependency]:
    """Occurrence rows addressed by a strict dependency subject."""
    if finding.category != "dependency":
        return []
    parsed = _parse_dep_subject(finding.subject_key)
    if parsed is None:
        return []
    kind = parsed[0]
    if kind == "count":
        return []
    if kind == "group":
        _kind, ecosystem, name, versions = parsed
        assert isinstance(versions, tuple)
        return [
            occurrence
            for occurrence in occurrences
            if occurrence.ecosystem == ecosystem
            and occurrence.canonical_name == name
            and (occurrence.resolved_version or "") in versions
        ]
    if kind == "unused":
        _kind, ecosystem, name = parsed
        return [
            occurrence
            for occurrence in occurrences
            if occurrence.ecosystem == ecosystem and occurrence.canonical_name == name
        ]
    if kind == "known":
        _kind, ecosystem, name, version, _advisory = parsed
        matched = [
            occurrence
            for occurrence in occurrences
            if occurrence.ecosystem == ecosystem
            and occurrence.canonical_name == name
            and (occurrence.resolved_version or "") == version
        ]
        if not matched:
            raise ValueError(
                f"Known-vulnerability finding {finding.rule_id!r} matches no occurrence."
            )
        return matched
    return []


def persist_domain_states(
    session: Session, analysis_id: str, states: list[DomainStateInput]
) -> None:
    """Persist one domain state per analysis area (docs/12 §4.9)."""
    _require_unsealed(session, analysis_id)
    if _kind_present(session, DomainState, analysis_id):
        raise ValueError(f"Domain states for analysis {analysis_id!r} were already persisted.")
    if sorted(state.area for state in states) != sorted(AREAS):
        raise ValueError("Domain states must cover exactly the four analysis areas.")
    for state in states:
        if state.state is not None and state.state not in DOMAIN_STATES:
            raise ValueError(f"Unknown domain state for {state.area!r}: {state.state!r}.")
        if state.state not in ("No findings detected", None) and not state.reason:
            raise ValueError(f"Domain state for {state.area!r} requires a reason.")
        session.add(
            DomainState(
                analysis_id=analysis_id, area=state.area, state=state.state, reason=state.reason
            )
        )
    session.flush()


def persist_rule_evaluations(
    session: Session,
    analysis: Analysis,
    rules: dict[str, Rule],
    evaluations: list[RuleEvaluationInput],
) -> None:
    """Persist one evaluation row per evaluated rule (docs/12 §4.9)."""
    _require_unsealed(session, analysis.id)
    if _kind_present(session, RuleEvaluation, analysis.id):
        raise ValueError(f"Rule evaluations for analysis {analysis.id!r} were already persisted.")
    rule_ids = sorted(evaluation.rule_id for evaluation in evaluations)
    if len(set(rule_ids)) != len(rule_ids):
        raise ValueError("Duplicate rule evaluations in evaluations batch.")
    for evaluation in evaluations:
        rule = rules.get(evaluation.rule_id)
        if rule is None:
            raise ValueError(f"Rule evaluation references an unknown rule: {evaluation.rule_id!r}.")
        if evaluation.state not in RULE_EVAL_STATES:
            raise ValueError(f"Unknown rule state for {evaluation.rule_id!r}.")
        if evaluation.state != "Evaluated" and not evaluation.reason:
            raise ValueError(f"Rule evaluation for {evaluation.rule_id!r} requires a reason.")
        session.add(
            RuleEvaluation(
                analysis_id=analysis.id,
                rule_id=evaluation.rule_id,
                rule_set_version=analysis.rule_set_version,
                state=evaluation.state,
                reason=evaluation.reason,
            )
        )
    session.flush()


def persist_file_coverages(
    session: Session, analysis_id: str, coverages: list[FileCoverageInput]
) -> None:
    """Persist sparse file coverages for non-Fully scopes (docs/12 §4.9)."""
    _require_unsealed(session, analysis_id)
    already = session.scalar(
        select(FileCoverage.id)
        .join(File, File.id == FileCoverage.file_id)
        .where(File.analysis_id == analysis_id)
    )
    if already is not None:
        raise ValueError(f"File coverages for analysis {analysis_id!r} were already persisted.")
    files = _files_by_path(session, analysis_id)
    seen: set[tuple[str, str, str]] = set()
    for coverage in coverages:
        if coverage.scope_kind not in ("area", "rule"):
            raise ValueError(f"Unknown coverage scope kind: {coverage.scope_kind!r}.")
        if coverage.state not in FILE_COVERAGE_STATES:
            raise ValueError(f"Unknown coverage state for {coverage.path!r}.")
        if coverage.state != "Fully analyzed" and not coverage.reason:
            raise ValueError(f"Coverage for {coverage.path!r} requires a reason.")
        if coverage.path not in files:
            raise ValueError(f"Coverage references an unknown file: {coverage.path!r}.")
        key = (coverage.path, coverage.scope_kind, coverage.scope_value)
        if key in seen:
            raise ValueError(f"Duplicate file coverage: {key!r}.")
        seen.add(key)
        session.add(
            FileCoverage(
                file_id=files[coverage.path].id,
                scope_kind=coverage.scope_kind,
                scope_value=coverage.scope_value,
                state=coverage.state,
                reason=coverage.reason,
            )
        )
    session.flush()


def persist_limitations(
    session: Session,
    analysis: Analysis,
    rules: dict[str, Rule],
    limitations: list[Limitation],
) -> None:
    """Persist analyzer limitations with canonical scope mapping (§6.5).

    Analyzer scopes (``analysis``, ``area``, ``area:rule``) map to canonical
    ``scope_kind`` values; a recorded rule with a path keeps both. Scopes
    outside the analyzer vocabulary raise instead of being coerced.
    """
    _require_unsealed(session, analysis.id)
    existing = session.scalar(
        select(LimitationRow.id).where(LimitationRow.analysis_id == analysis.id)
    )
    if existing is not None:
        raise ValueError(f"Limitations for analysis {analysis.id!r} were already persisted.")
    files = _files_by_path(session, analysis.id)
    for limitation in limitations:
        scope_kind, area, rule_id = _limitation_scope(limitation, rules, analysis.rule_set_version)
        file_id: str | None = None
        if limitation.path is not None:
            if limitation.path not in files:
                raise ValueError(f"Limitation references an unknown file: {limitation.path!r}.")
            file_id = files[limitation.path].id
        session.add(
            LimitationRow(
                analysis_id=analysis.id,
                scope_kind=scope_kind,
                area=area,
                rule_id=rule_id,
                rule_set_version=analysis.rule_set_version if rule_id is not None else None,
                file_id=file_id,
                file_path=limitation.path,
                reason=limitation.reason,
            )
        )
    session.flush()


def _limitation_scope(
    limitation: Limitation, rules: dict[str, Rule], rule_set_version: str
) -> tuple[str, str | None, str | None]:
    """Map an analyzer limitation scope to (scope_kind, area, rule_id)."""
    scope = limitation.scope.strip()
    if scope == "analysis":
        if limitation.rule_id is not None or limitation.path is not None:
            raise ValueError("Analysis-scope limitation must not carry rule or path.")
        return "analysis", None, None
    if ":" in scope:
        area, _, _declared = scope.partition(":")
        if area not in AREAS:
            raise ValueError(f"Unknown limitation area: {scope!r}.")
        rule_id = limitation.rule_id
        if rule_id is not None:
            rule = rules.get(rule_id)
            if rule is None:
                raise ValueError(f"Limitation references an unknown rule: {rule_id!r}.")
            if rule.category != area:
                raise ValueError(f"Limitation rule area mismatch: {scope!r}.")
            return "rule", area, rule_id
        if limitation.path is not None:
            return "file", area, None
        return "area", area, None
    if scope in AREAS:
        return "area", scope, None
    if scope in LIMITATION_SCOPES:
        return scope, None, None
    raise ValueError(f"Unknown limitation scope: {scope!r}.")


def mark_completed(
    session: Session, analysis: Analysis, *, outcome: str, explanation: str | None
) -> Analysis:
    """Record the terminal outcome with a user-safe explanation (docs/13 §6.6)."""
    _require_unsealed(session, analysis.id)
    if analysis.outcome is not None:
        raise ValueError("Terminal analysis outcome must not change.")
    if outcome not in SEALABLE_OUTCOMES and outcome != "Failed":
        raise ValueError(f"Unknown analysis outcome: {outcome!r}.")
    if outcome == "Completed with limitations" and not (explanation or "").strip():
        raise ValueError("Completed with limitations requires an explanation.")
    analysis.outcome = outcome
    analysis.completed_at = utcnow()
    analysis.explanation = explanation
    session.flush()
    return analysis


def seal_snapshot(session: Session, analysis_id: str) -> AnalysisSnapshot:
    """Seal a completed snapshot after contract validation (docs/12 §4.8).

    Validates the completed outcome, exactly four domain states, rule
    evaluations covering every registered rule of areas with present
    sections, the required explanation, and strict Completed purity (no
    recorded limitation) — then inserts the single snapshot row that
    freezes the analysis.
    """
    analysis = session.get(Analysis, analysis_id)
    if analysis is None:
        raise ValueError(f"Unknown analysis: {analysis_id!r}.")
    if (
        session.scalar(
            select(AnalysisSnapshot.id).where(AnalysisSnapshot.analysis_id == analysis_id)
        )
        is not None
    ):
        raise SealedSnapshotError(f"Analysis {analysis_id!r} is already sealed.")
    if analysis.outcome not in SEALABLE_OUTCOMES:
        raise IncompleteSnapshotError(
            f"Only completed analyses seal; outcome is {analysis.outcome!r}."
        )
    if (
        analysis.outcome == "Completed with limitations"
        and not (analysis.explanation or "").strip()
    ):
        raise IncompleteSnapshotError("Completed with limitations requires an explanation.")
    if analysis.outcome == "Completed" and (
        session.scalar(select(LimitationRow.id).where(LimitationRow.analysis_id == analysis_id))
        is not None
    ):
        raise IncompleteSnapshotError(
            "Completed must not coexist with a recorded limitation (docs/13 §6.6)."
        )
    domains = session.scalars(
        select(DomainState).where(DomainState.analysis_id == analysis_id)
    ).all()
    if sorted(domain.area for domain in domains) != sorted(AREAS):
        raise IncompleteSnapshotError("Snapshot requires exactly four domain states.")
    null_areas = {
        domain.area
        for domain in domains
        if domain.state in ("Analysis not performed", "Analysis failed", "Analysis unavailable")
    }
    registered = session.scalars(
        select(Rule).where(Rule.rule_set_version == analysis.rule_set_version)
    ).all()
    evaluated = {
        row.rule_id
        for row in session.scalars(
            select(RuleEvaluation).where(RuleEvaluation.analysis_id == analysis_id)
        ).all()
    }
    missing = sorted(
        rule.rule_id
        for rule in registered
        if rule.category not in null_areas and rule.rule_id not in evaluated
    )
    if missing:
        raise IncompleteSnapshotError(f"Snapshot misses rule evaluations: {missing!r}.")
    snapshot = AnalysisSnapshot(
        analysis_id=analysis_id, sealed_at=utcnow(), outcome=analysis.outcome
    )
    session.add(snapshot)
    session.flush()
    return snapshot


def get_snapshot(session: Session, analysis_id: str) -> AnalysisSnapshot | None:
    """Return an analysis' snapshot row, or None when not sealed."""
    return session.scalar(
        select(AnalysisSnapshot).where(AnalysisSnapshot.analysis_id == analysis_id)
    )


def load_snapshot_data(session: Session, analysis_id: str) -> SnapshotData:
    """Load every persisted row of one sealed snapshot (docs/12 §13.2).

    Raises when the analysis is unknown or has no sealed snapshot: only
    sealed snapshots are reproducible units for serialization and
    comparison.
    """
    analysis = session.get(Analysis, analysis_id)
    if analysis is None:
        raise ValueError(f"Unknown analysis: {analysis_id!r}.")
    snapshot = get_snapshot(session, analysis_id)
    if snapshot is None:
        raise IncompleteSnapshotError(f"Analysis {analysis_id!r} has no sealed snapshot.")
    repository = session.get(Repository, analysis.repository_id)
    if repository is None:
        raise IncompleteSnapshotError(f"Analysis {analysis_id!r} has no repository.")
    rules = {
        row.rule_id: row.name
        for row in session.scalars(
            select(Rule)
            .where(Rule.rule_set_version == analysis.rule_set_version)
            .order_by(Rule.rule_id)
        ).all()
    }
    findings = list(
        session.scalars(
            select(FindingRow)
            .where(FindingRow.analysis_id == analysis_id)
            .options(
                selectinload(FindingRow.locations),
                selectinload(FindingRow.modules),
                selectinload(FindingRow.dependencies),
            )
            .order_by(FindingRow.rule_id, FindingRow.location_path, FindingRow.finding_id)
        ).all()
    )
    evaluations = list(
        session.scalars(
            select(RuleEvaluation)
            .where(RuleEvaluation.analysis_id == analysis_id)
            .order_by(RuleEvaluation.rule_id)
        ).all()
    )
    metrics = list(
        session.scalars(
            select(ArchitectureMetric)
            .where(ArchitectureMetric.analysis_id == analysis_id)
            .order_by(
                ArchitectureMetric.area,
                ArchitectureMetric.metric_name,
                ArchitectureMetric.subject_path,
                ArchitectureMetric.subject_name,
            )
        ).all()
    )
    modules = list(
        session.scalars(
            select(Module).where(Module.analysis_id == analysis_id).order_by(Module.module_id)
        ).all()
    )
    module_dependencies = list(
        session.scalars(
            select(ModuleDependency)
            .where(ModuleDependency.analysis_id == analysis_id)
            .order_by(ModuleDependency.source_id, ModuleDependency.target_text)
        ).all()
    )
    dependencies = list(
        session.scalars(
            select(Dependency)
            .where(Dependency.analysis_id == analysis_id)
            .options(
                selectinload(Dependency.relationships),
                selectinload(Dependency.advisories),
            )
            .order_by(
                Dependency.ecosystem,
                Dependency.canonical_name,
                Dependency.resolved_version,
                Dependency.source_manifest,
            )
        ).all()
    )
    files = list(
        session.scalars(
            select(File).where(File.analysis_id == analysis_id).order_by(File.path)
        ).all()
    )
    file_ids = {row.id for row in files}
    coverages: list[FileCoverage] = []
    if file_ids:
        coverages = list(
            session.scalars(select(FileCoverage).where(FileCoverage.file_id.in_(file_ids))).all()
        )
    domains = list(
        session.scalars(
            select(DomainState)
            .where(DomainState.analysis_id == analysis_id)
            .order_by(DomainState.area)
        ).all()
    )
    limitations = list(
        session.scalars(
            select(LimitationRow)
            .where(LimitationRow.analysis_id == analysis_id)
            .order_by(
                LimitationRow.scope_kind,
                LimitationRow.area,
                LimitationRow.rule_id,
                LimitationRow.file_path,
            )
        ).all()
    )
    return SnapshotData(
        analysis=analysis,
        repository=repository,
        snapshot=snapshot,
        rules=rules,
        findings=findings,
        rule_evaluations=evaluations,
        metrics=metrics,
        modules=modules,
        module_dependencies=module_dependencies,
        dependencies=dependencies,
        files=files,
        file_coverages=coverages,
        domain_states=domains,
        limitations=limitations,
    )


def canonical_result(
    session: Session, analysis_id: str, comparison: dict[str, object] | None = None
) -> dict[str, object]:
    """Build the canonical JSON-compatible result of a sealed snapshot."""
    data = load_snapshot_data(session, analysis_id)
    data.comparison = comparison
    return build_canonical_result(data)


def compare_analyses(session: Session, base_id: str, target_id: str) -> ComparisonResult:
    """Compare two sealed snapshots of one repository (docs/13 §15)."""
    base = load_snapshot_data(session, base_id)
    target = load_snapshot_data(session, target_id)
    return compare_snapshots(snapshot_view_from_data(base), snapshot_view_from_data(target))


__all__ = [
    "ADVISORY_STATUSES",
    "MODULE_RESOLUTIONS",
    "SEALABLE_OUTCOMES",
    "ComparisonResult",
    "DependencyAdvisoryInput",
    "DependencyInput",
    "DependencyKey",
    "DomainStateInput",
    "FileCoverageInput",
    "IncompleteSnapshotError",
    "MetricInput",
    "ModuleDepInput",
    "ModuleInput",
    "RuleDefinition",
    "RuleEvaluationInput",
    "SealedSnapshotError",
    "canonical_result",
    "compare_analyses",
    "ensure_rules",
    "get_snapshot",
    "load_snapshot_data",
    "mark_completed",
    "persist_dependencies",
    "persist_domain_states",
    "persist_file_coverages",
    "persist_findings",
    "persist_limitations",
    "persist_metrics",
    "persist_modules",
    "record_results_context",
    "seal_snapshot",
]
