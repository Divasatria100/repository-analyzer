"""Production analysis pipeline: parse → NCM → analyze → aggregate → persist → seal.

The single post-ingestion orchestrator for VS-003 (parsing → Normalized
Code Model) and VS-004 (all four analyzer domains → persisted results →
sealed snapshot). It resumes the already-persisted analysis exactly where
``continue_ingestion`` stops (``DetectingLanguages``), runs the parse
phase, then drives every analyzer through the shared runner, aggregates
their outputs, and writes the result snapshot.

Boundaries (mirrors ``run_analysis_to_index``):
- Only analyses still in ``Queued`` stage are claimed; anything else is a
  no-op so retries or concurrent dispatches never duplicate work.
- The four analyzers run with per-rule isolation (``run_analyzer``); one
  domain failing never stops the others, and a failed domain is recorded
  rather than silently read as clean.
- Retrieval/ingestion failures are already durable (``continue_ingestion``
  commits Failed); any later unexpected failure marks the analysis Failed
  with a user-safe explanation and re-raises, so the terminal state
  survives the rollback.
- The disposable workspace is cleaned on every exit path; cleanup is
  best-effort and never changes the recorded result.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.analyzers.architecture.analyzer import ArchitectureAnalyzer
from app.analyzers.architecture.layers import infer_layers
from app.analyzers.architecture.metrics import (
    LINES_BASIS,
    class_line_count,
    class_method_count,
    coupling_def_1,
    fan_in,
    fan_out,
    function_complexity_lower_bound,
    function_line_count,
    module_declaration_count,
    module_line_count,
)
from app.analyzers.architecture.models import MetricValue
from app.analyzers.code_structure.analyzer import CodeStructureAnalyzer
from app.analyzers.context import AnalysisContext
from app.analyzers.dependency.analyzer import (
    DependencyAnalyzer,
    Inventory,
    ManifestProvider,
    dependency_provider_from_workspace,
)
from app.analyzers.dependency.models import SupportState
from app.analyzers.dependency.osv import OsvClient
from app.analyzers.runner import run_analyzer
from app.analyzers.security.analyzer import SecurityAnalyzer
from app.analyzers.security.source import SourceProvider, WorkspaceSourceProvider
from app.analyzers.thresholds import default_thresholds
from app.core.database import session_scope
from app.core.logging import get_logger, log_event, log_exception
from app.models.indexing import File as FileRow
from app.models.repository import Analysis, Repository
from app.repositories import ingestion as persistence
from app.repositories.indexing import get_files
from app.repositories.results import (
    DependencyInput,
    DomainStateInput,
    FileCoverageInput,
    MetricInput,
    ModuleDepInput,
    ModuleInput,
    RuleDefinition,
    RuleEvaluationInput,
    ensure_rules,
    mark_completed,
    persist_dependencies,
    persist_domain_states,
    persist_file_coverages,
    persist_findings,
    persist_limitations,
    persist_metrics,
    persist_modules,
    persist_rule_evaluations,
    record_results_context,
    seal_snapshot,
)
from app.repository.errors import ConcurrencyExhaustedError, IngestionError
from app.repository.identity import normalize_github_url
from app.repository.ingestion import continue_ingestion
from app.repository.runner import RunnerDependencies
from app.results.aggregation import (
    FILE_FAILED,
    FULLY_ANALYZED,
    NOT_ANALYZED,
    PARTIALLY_ANALYZED,
    AnalysisMeta,
    DomainInput,
    FileMeta,
    RuleCoverage,
    aggregate,
    default_configuration,
)

_logger = get_logger("analysis_pipeline")

#: Manifest support state to the canonical file-coverage vocabulary.
_SUPPORT_TO_COVERAGE = {
    SupportState.SUPPORTED: FULLY_ANALYZED,
    SupportState.PARTIAL: PARTIALLY_ANALYZED,
    SupportState.FAILED: FILE_FAILED,
    SupportState.UNSUPPORTED: NOT_ANALYZED,
    SupportState.NOT_APPLICABLE: NOT_ANALYZED,
}


class AnalysisPipelineError(Exception):
    """A stage could not establish a usable result (user-safe, no internals)."""


def run_analysis_pipeline(
    *,
    analysis_id: str,
    deps: RunnerDependencies,
    remote_url_override: str | None = None,
    allow_local_paths: bool = False,
    source_provider: SourceProvider | None = None,
    manifest_provider: ManifestProvider | None = None,
    osv_client: OsvClient | None = None,
) -> None:
    """Continue one persisted analysis through analysis and sealing.

    ``remote_url_override``/``allow_local_paths`` and the provider/OSV
    overrides exist ONLY so tests can inject local fixtures and fakes;
    production callers must omit them.
    """
    with session_scope(deps.session_factory) as session:
        analysis = session.get(Analysis, analysis_id)
        if analysis is None:
            log_event(
                _logger,
                logging.WARNING,
                "analysis.pipeline.unknown",
                "Pipeline invoked for unknown analysis; nothing to do",
                analysis_id=analysis_id,
            )
            return
        if analysis.outcome is not None or analysis.stage != "Queued":
            log_event(
                _logger,
                logging.INFO,
                "analysis.pipeline.skipped",
                "Pipeline skipping non-queued analysis",
                analysis_id=analysis_id,
                stage=analysis.stage,
                outcome=analysis.outcome,
            )
            return
        repository = session.get(Repository, analysis.repository_id)
        if repository is None:
            persistence.mark_failed(session, analysis, "The analysis could not be completed.")
            return
        identity = normalize_github_url(repository.normalized_url)
        workspace: Path | None = None
        try:
            default_branch = repository.default_branch
            if not default_branch:
                default_branch = deps.github.get_repository(identity).default_branch
            continued = continue_ingestion(
                session=session,
                analysis=analysis,
                identity=identity,
                default_branch=default_branch,
                requested_branch=analysis.requested_branch,
                requested_commit=analysis.requested_commit,
                settings=deps.settings,
                github=deps.github,
                workspaces=deps.workspaces,
                retrieval=deps.retrieval,
                concurrency=deps.concurrency,
                remote_url_override=remote_url_override,
                allow_local_paths=allow_local_paths,
            )
            workspace = continued.workspace
            aggregated = _run_stages(
                session=session,
                analysis=analysis,
                repository=repository,
                deps=deps,
                workspace=workspace,
                source_provider=source_provider,
                manifest_provider=manifest_provider,
                osv_client=osv_client,
            )
            outcome = aggregated.outcome
            explanation = aggregated.outcome_explanation or None
            mark_completed(session, analysis, outcome=outcome, explanation=explanation)
            if outcome in ("Completed", "Completed with limitations"):
                seal_snapshot(session, analysis.id)
            cleanup = deps.workspaces.cleanup(workspace, analysis.id)
            analysis.cleanup_status = "completed" if cleanup.removed else "failed"
            workspace = None
            session.commit()
        except ConcurrencyExhaustedError as exc:
            persistence.mark_failed(session, analysis, exc.user_message)
            session.commit()
        except IngestionError as exc:
            if analysis.outcome is None:
                persistence.mark_failed(session, analysis, exc.user_message)
                session.commit()
            raise
        except Exception as exc:
            if analysis.outcome is None:
                persistence.mark_failed(session, analysis, "The analysis could not be completed.")
                session.commit()
            log_exception(
                _logger,
                "analysis.pipeline.unexpected",
                exc,
                "Analysis pipeline failed unexpectedly",
                analysis_id=analysis_id,
                error_type=type(exc).__name__,
            )
            raise
        finally:
            if workspace is not None:
                deps.workspaces.cleanup(workspace, analysis_id)


def _run_stages(
    *,
    session: Session,
    analysis: Analysis,
    repository: Repository,
    deps: RunnerDependencies,
    workspace: Path,
    source_provider: SourceProvider | None,
    manifest_provider: ManifestProvider | None,
    osv_client: OsvClient | None,
) -> Any:
    """Parse, analyze, aggregate, and persist; return the aggregated result."""
    persistence.set_stage(session, analysis, "ParsingSource")
    parse = run_parse_phase(
        session=session,
        analysis_id=analysis.id,
        workspace=workspace,
        workspaces=deps.workspaces,
        settings=deps.settings,
    )
    persistence.set_stage(session, analysis, "BuildingCodeModel")
    ncm = parse.repository
    if ncm is None:  # pragma: no cover - run_parse_phase always returns an NCM
        raise AnalysisPipelineError("The normalized code model could not be built.")

    persistence.set_stage(session, analysis, "RunningAnalysis")
    thresholds = default_thresholds()
    file_rows = get_files(session, analysis.id)
    source = (
        source_provider
        if source_provider is not None
        else WorkspaceSourceProvider(deps.workspaces, workspace)
    )
    manifest = (
        manifest_provider
        if manifest_provider is not None
        else dependency_provider_from_workspace(
            workspaces=deps.workspaces,
            workspace=workspace,
            indexed_paths=[row.path for row in file_rows],
            file_max_bytes=deps.settings.operational.file_max_size_bytes,
        )
    )
    analyzers = [
        SecurityAnalyzer(source),
        ArchitectureAnalyzer(source),
        DependencyAnalyzer(manifest, osv_client),
        CodeStructureAnalyzer(source),
    ]
    context = AnalysisContext(
        analysis_id=analysis.id,
        repository_id=analysis.repository_id,
        owner=repository.owner,
        name=repository.name,
        canonical_url=repository.normalized_url,
        resolved_branch=analysis.resolved_branch or "",
        resolved_commit_sha=analysis.resolved_commit_sha or "",
        ncm=ncm,
        analyzer_version=analysis.analyzer_version,
        rule_set_version=analysis.rule_set_version,
        thresholds=thresholds,
        requested_branch=analysis.requested_branch,
        requested_commit=analysis.requested_commit,
    )
    results = [run_analyzer(analyzer, context) for analyzer in analyzers]

    persistence.set_stage(session, analysis, "AggregatingResults")
    aggregated = _aggregate_and_persist(
        session=session,
        analysis=analysis,
        repository=repository,
        context=context,
        analyzers=analyzers,
        results=results,
        ncm=ncm,
        file_rows=file_rows,
        thresholds=thresholds,
        osv_client=osv_client,
    )
    persistence.set_stage(session, analysis, "GeneratingReports")
    return aggregated


def _aggregate_and_persist(
    *,
    session: Session,
    analysis: Analysis,
    repository: Repository,
    context: AnalysisContext,
    analyzers: list[Any],
    results: list[Any],
    ncm: Any,
    file_rows: list[FileRow],
    thresholds: Any,
    osv_client: OsvClient | None,
) -> Any:
    """Aggregate analyzer outputs and persist every result section."""
    file_metas = [_file_meta(row) for row in file_rows]
    definitions, registered = _rule_definitions(analyzers)

    coverage_failed: set[str] = set()
    coverages: dict[str, tuple[RuleCoverage, ...]] = {}
    for analyzer, result in zip(analyzers, results, strict=True):
        area = result.analyzer_id
        try:
            coverages[area] = _normalize_coverages(area, analyzer, ncm, context)
        except Exception as exc:  # pragma: no cover - defensive isolation
            coverage_failed.add(area)
            log_exception(
                _logger,
                "analysis.pipeline.coverage.failed",
                exc,
                "Coverage computation failed; domain recorded as failed",
                analysis_id=analysis.id,
                area=area,
            )
    domains = [
        _domain_input(
            result,
            coverages.get(result.analyzer_id, ()),
            result.analyzer_id in coverage_failed,
        )
        for result in results
    ]

    configuration = default_configuration(thresholds.effective())
    meta = AnalysisMeta(
        analysis_id=analysis.id,
        repository_id=analysis.repository_id,
        resolved_commit_sha=analysis.resolved_commit_sha,
        resolved_branch=analysis.resolved_branch,
        analyzer_version=analysis.analyzer_version,
        rule_set_version=analysis.rule_set_version,
        configuration=configuration,
    )

    inventory = _dependency_inventory(analyzers, context)
    manifest_states = _manifest_states(inventory)

    aggregated = aggregate(
        meta,
        file_metas,
        domains,
        manifest_states=manifest_states,
        registered_rules=registered,
    )

    rules = ensure_rules(session, analysis.rule_set_version, definitions)
    record_results_context(
        session,
        analysis,
        configuration=configuration,
        advisory_source="OSV" if osv_client is not None else None,
        advisory_status="succeeded" if osv_client is not None else None,
    )

    module_inputs, architecture_metrics = _architecture_inputs(analyzers, context)
    dependency_inputs = _dependency_inputs(inventory)
    code_metrics = _code_structure_metrics(analyzers, context)

    persist_modules(session, analysis.id, module_inputs)
    persist_dependencies(session, analysis.id, dependency_inputs)
    persist_metrics(session, analysis.id, architecture_metrics + code_metrics)
    persist_findings(session, analysis, rules, list(aggregated.findings))
    persist_domain_states(
        session,
        analysis.id,
        [DomainStateInput(d.category, d.state, d.reason) for d in aggregated.domains],
    )
    persist_rule_evaluations(
        session,
        analysis,
        rules,
        [RuleEvaluationInput(e.rule_id, e.state, e.reason) for e in aggregated.rule_evaluations],
    )
    persist_file_coverages(
        session,
        analysis.id,
        [
            FileCoverageInput(c.path, c.scope_kind, c.scope_value, c.state, c.reason)
            for c in aggregated.file_coverages
        ],
    )
    persist_limitations(session, analysis, rules, list(aggregated.limitations))
    return aggregated


def _file_meta(row: FileRow) -> FileMeta:
    """Map one persisted File row to aggregation file metadata."""
    return FileMeta(
        path=row.path,
        file_type=row.file_type,
        extension=row.extension,
        size=row.size,
        language=row.language,
        support_status=row.support_status,
        is_binary=row.is_binary,
        is_generated=row.is_generated,
        excluded=row.excluded,
        exclusion_reason=row.exclusion_reason,
        eligibility=row.eligibility,
        eligibility_reason=row.eligibility_reason or "",
        parse_result=row.parse_result,
    )


def _rule_definitions(
    analyzers: list[Any],
) -> tuple[list[RuleDefinition], dict[str, tuple[str, ...]]]:
    """Build the rule registry inputs and per-area registered rule ids."""
    definitions: list[RuleDefinition] = []
    registered: dict[str, list[str]] = {}
    seen: set[str] = set()
    for analyzer in analyzers:
        for rule in analyzer.rules():
            metadata = rule.metadata
            if metadata.rule_id in seen:
                continue
            seen.add(metadata.rule_id)
            definitions.append(
                RuleDefinition(
                    rule_id=metadata.rule_id,
                    name=metadata.name,
                    category=metadata.category,
                    description=metadata.description,
                    default_severity=metadata.default_severity,
                    documentation_ref=metadata.documentation_ref or None,
                )
            )
            registered.setdefault(metadata.category, []).append(metadata.rule_id)
    return definitions, {area: tuple(sorted(set(ids))) for area, ids in registered.items()}


def _normalize_coverages(
    area: str, analyzer: Any, ncm: Any, context: AnalysisContext
) -> tuple[RuleCoverage, ...]:
    """Normalize either analyzer coverage vocabulary to ``RuleCoverage``."""
    if area == "dependency":
        rows = analyzer.coverage(context)
        return tuple(
            RuleCoverage(
                rule_id=str(row["rule_id"]),
                status=str(row["status"]),
                reason=str(row.get("reason", "") or ""),
            )
            for row in rows
        )
    rows = analyzer.coverage(ncm)
    return tuple(
        RuleCoverage(rule_id=row.rule_id, status=row.status.value, reason=row.reason)
        for row in rows
    )


def _domain_input(
    result: Any, coverages: tuple[RuleCoverage, ...], coverage_failed: bool
) -> DomainInput:
    """Build one aggregation domain bundle from an analyzer result."""
    rule_failures = tuple(
        rule_result.rule_id
        for rule_result in result.rule_results
        if rule_result.failure is not None
    )
    limitations = tuple(
        limitation for rule_result in result.rule_results for limitation in rule_result.limitations
    )
    return DomainInput(
        analyzer_id=result.analyzer_id,
        category=result.analyzer_id,
        findings=result.findings,
        rule_failures=rule_failures,
        analyzer_failed=result.failed or coverage_failed,
        coverages=coverages,
        limitations=limitations,
    )


def _dependency_inventory(analyzers: list[Any], context: AnalysisContext) -> Inventory | None:
    """Return the dependency analyzer's normalized inventory, or None."""
    for analyzer in analyzers:
        if analyzer.id == "dependency":
            return analyzer.inventory_for(context)  # type: ignore[no-any-return]
    return None


def _manifest_states(inventory: Inventory | None) -> dict[str, str]:
    """Map manifest support states to canonical file-coverage states."""
    if inventory is None:
        return {}
    return {
        outcome.ref.path: _SUPPORT_TO_COVERAGE[outcome.ref.support_state]
        for outcome in inventory.outcomes
    }


def _architecture_inputs(
    analyzers: list[Any], context: AnalysisContext
) -> tuple[list[ModuleInput], list[MetricInput]]:
    """Build module/dependency rows and metrics from the architecture graph."""
    analyzer = next((item for item in analyzers if item.id == "architecture"), None)
    if analyzer is None:  # pragma: no cover - analyzers always include architecture
        return [], []
    prepared = analyzer.prepared_for(context)
    graph = prepared.report.graph
    layers = infer_layers(sorted(graph.nodes))
    module_inputs: list[ModuleInput] = []
    metrics: list[MetricInput] = []
    seen: set[tuple[str, str, str, str]] = set()

    for node_id in sorted(graph.nodes):
        node = graph.nodes[node_id]
        references: list[ModuleDepInput] = []
        for (source, target), edge in sorted(graph.edges.items()):
            if source != node_id:
                continue
            first = edge.locations[0] if edge.locations else None
            references.append(
                ModuleDepInput(
                    target=target,
                    target_text=target,
                    resolution="internal",
                    file_path=node_id,
                    line=first[1] if first is not None else None,
                    column=first[2] if first is not None else None,
                    conditional=edge.conditional,
                    deferred=edge.deferred,
                    locations=tuple(edge.locations),
                )
            )
        for item in prepared.report.unresolved:
            if item.path != node_id:
                continue
            references.append(
                ModuleDepInput(
                    target=None,
                    target_text=item.target_text,
                    resolution="external" if item.reason == "external" else "unresolved",
                    file_path=item.path,
                    line=item.line,
                    column=item.column,
                )
            )
        module_inputs.append(
            ModuleInput(
                module_id=node_id,
                file_path=node_id,
                partially_represented=node.partially_represented,
                layer=layers[node_id].layer,
                dependencies=tuple(references),
            )
        )
        module = prepared.modules.get(node_id)
        if module is None:
            continue
        _push_metric(metrics, seen, _value_metric(fan_out(graph, node_id), node_id, "", "module"))
        _push_metric(metrics, seen, _value_metric(fan_in(graph, node_id), node_id, "", "module"))
        _push_metric(
            metrics, seen, _value_metric(coupling_def_1(graph, node_id), node_id, "", "module")
        )
        lines = module_line_count(module, prepared.source_texts.get(node_id))
        _push_metric(
            metrics,
            seen,
            _raw_metric("lines_of_code", node_id, "", "module", lines, LINES_BASIS),
        )
        _push_metric(
            metrics,
            seen,
            _raw_metric(
                "declaration_count",
                node_id,
                "",
                "module",
                module_declaration_count(module),
                "classes + functions (methods counted once, as functions)",
            ),
        )
        for cls in sorted(module.classes, key=lambda item: item.qualified_name):
            _push_metric(
                metrics,
                seen,
                _raw_metric(
                    "lines_of_code",
                    node_id,
                    cls.qualified_name,
                    "class",
                    class_line_count(cls),
                    LINES_BASIS,
                ),
            )
            _push_metric(
                metrics,
                seen,
                _raw_metric(
                    "method_count",
                    node_id,
                    cls.qualified_name,
                    "class",
                    class_method_count(module, cls),
                    "methods declared in the class",
                ),
            )
        for fun in sorted(module.functions, key=lambda item: item.qualified_name):
            _push_metric(
                metrics,
                seen,
                _raw_metric(
                    "lines_of_code",
                    node_id,
                    fun.qualified_name,
                    "function",
                    function_line_count(fun),
                    LINES_BASIS,
                ),
            )
            _push_metric(
                metrics,
                seen,
                _value_metric(
                    function_complexity_lower_bound(module, fun),
                    node_id,
                    fun.qualified_name,
                    "function",
                ),
            )
    return module_inputs, metrics


def _value_metric(
    value: MetricValue, subject_path: str, subject_name: str, subject_kind: str
) -> MetricInput:
    """Map an architecture ``MetricValue`` (fan/coupling/complexity)."""
    return MetricInput(
        area="architecture",
        metric_name="coupling" if value.name == "coupling-def-1" else value.name,
        subject_kind=subject_kind,
        subject_path=subject_path,
        subject_name=subject_name,
        value=value.value,
        availability="available" if value.value is not None else "unavailable",
        potentially_incomplete=value.potentially_incomplete,
        basis=value.basis or None,
    )


def _raw_metric(
    metric_name: str,
    subject_path: str,
    subject_name: str,
    subject_kind: str,
    value: int | None,
    basis: str | None,
) -> MetricInput:
    """Build one metric from a plain integer measurement."""
    return MetricInput(
        area="architecture",
        metric_name=metric_name,
        subject_kind=subject_kind,
        subject_path=subject_path,
        subject_name=subject_name,
        value=value,
        availability="available" if value is not None else "unavailable",
        basis=basis,
    )


def _push_metric(
    metrics: list[MetricInput], seen: set[tuple[str, str, str, str]], metric: MetricInput
) -> None:
    """Append a metric once per unique subject (deterministic dedupe)."""
    key = (metric.metric_name, metric.subject_kind, metric.subject_path, metric.subject_name)
    if key in seen:
        return
    seen.add(key)
    metrics.append(metric)


def _dependency_inputs(inventory: Inventory | None) -> list[DependencyInput]:
    """Map normalized occurrences to persistence inputs (deduplicated)."""
    if inventory is None:
        return []
    inputs: list[DependencyInput] = []
    seen: set[Any] = set()
    for occurrence in inventory.occurrences:
        item = DependencyInput(
            ecosystem=occurrence.ecosystem,
            canonical_name=occurrence.canonical_name,
            original_name=occurrence.original_name,
            source_manifest=occurrence.source_file,
            section=occurrence.section,
            constraint=occurrence.constraint,
            resolved_version=occurrence.resolved_version,
            dependency_class=occurrence.dependency_class.value,
            runtime_context=occurrence.runtime_context,
            source_line=occurrence.source_line,
            kind=occurrence.kind,
        )
        key = item.key()
        if key in seen:
            continue
        seen.add(key)
        inputs.append(item)
    return inputs


def _code_structure_metrics(analyzers: list[Any], context: AnalysisContext) -> list[MetricInput]:
    """Per-function complexity, nesting, and parameter measurements."""
    analyzer = next((item for item in analyzers if item.id == "code_structure"), None)
    if analyzer is None:  # pragma: no cover - analyzers always include code_structure
        return []
    measurements = analyzer.measurements_for(context)
    metrics: list[MetricInput] = []
    seen: set[tuple[str, str, str, str]] = set()
    for _key, values in sorted(measurements.items()):
        for metric_name in ("complexity", "nesting_depth", "parameter_count"):
            measurement = values.get(metric_name)
            if measurement is None:
                continue
            metric = MetricInput(
                area="code_structure",
                metric_name=metric_name,
                subject_kind="function",
                subject_path=measurement.path,
                subject_name=measurement.qualified_name,
                value=measurement.value,
                availability="available" if measurement.value is not None else "unavailable",
                potentially_incomplete=measurement.potentially_incomplete,
                basis=measurement.basis or None,
            )
            _push_metric(metrics, seen, metric)
    return metrics


# Re-exported for callers that build the pipeline in tests.
__all__ = ["AnalysisPipelineError", "run_analysis_pipeline"]

# Imported late to keep the module-level import graph flat.
from app.parsers.pipeline import run_parse_phase  # noqa: E402  (import order intentional)
