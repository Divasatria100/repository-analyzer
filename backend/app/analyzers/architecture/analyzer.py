"""Architecture analyzer execution pipeline (Phase 9, TASK-123–133).

The ``architecture`` analyzer runs the nine registered V1.0 rules
(docs/08 §6, ARCH-REQ-036) through the existing Phase 6 machinery:

* identity via :class:`app.analyzers.base.Analyzer` (``id = "architecture"``),
* deterministic rule-ID order, per-rule failure isolation (inherited),
* findings through the common Finding model only (no parallel model).

The analyzer consumes :class:`AnalysisContext` (NCM + versions +
thresholds) plus an optional narrow ``SourceProvider`` for bounded
read-as-data excerpts (reused from the security analyzer layer). It never
imports parsers, never executes repository code, and never touches the
network. Severity follows the §11.1 baseline mapping (Low default; Medium
when aggravated); observation framing stays investigatory
(ARCH-REQ-006/008) and no architecture score is ever produced
(ARCH-REQ-081/122).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app.analyzers.architecture import cycles as cycle_analysis
from app.analyzers.architecture.graph import build_graph
from app.analyzers.architecture.layers import (
    LAYER_RANK,
    UNKNOWN,
    LayerAssignment,
    find_violations,
    infer_layers,
)
from app.analyzers.architecture.metadata import (
    ARCHITECTURE_ANALYZER_ID,
    ARCHITECTURE_ANALYZER_VERSION,
    ARCHITECTURE_RULE_SPECS,
    CIRCULAR_DEPENDENCY_SPEC,
    HIGH_COUPLING_SPEC,
    HIGH_FAN_IN_SPEC,
    HIGH_FAN_OUT_SPEC,
    LARGE_CLASS_SPEC,
    LARGE_FUNCTION_SPEC,
    LARGE_MODULE_SPEC,
    LAYER_VIOLATION_SPEC,
    MULTIPLE_RESPONSIBILITY_SPEC,
    ArchitectureRuleSpec,
)
from app.analyzers.architecture.metrics import (
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
from app.analyzers.architecture.models import ExtractionReport
from app.analyzers.architecture.responsibility import (
    build_candidate,
    collect_signals,
    graph_context_for_candidate,
    is_candidate,
)
from app.analyzers.base import Analyzer
from app.analyzers.findings import (
    Confidence,
    Evidence,
    Finding,
    Limitation,
    Severity,
    create_finding,
)
from app.analyzers.rules import (
    RegisteredRule,
    RuleExecutionContext,
    RuleMetadata,
    RuleOutcome,
)
from app.analyzers.security.coverage import Coverage, CoverageStatus
from app.analyzers.security.evidence import build_security_evidence
from app.analyzers.security.source import SourceProvider
from app.core.logging import get_logger, log_event
from app.ncm import NcmRepository, NormalizedModule, SourceLocation

_logger = get_logger("analyzers.architecture")


@dataclass
class PreparedAnalysis:
    """Shared per-analysis inputs built once and reused by every rule."""

    report: ExtractionReport
    modules: dict[str, NormalizedModule]
    source_texts: dict[str, tuple[str, ...]]
    partial_paths: set[str]
    unresolved_paths: set[str]


def _read_sources(source: SourceProvider | None, paths: list[str]) -> dict[str, tuple[str, ...]]:
    texts: dict[str, tuple[str, ...]] = {}
    if source is None:
        return texts
    for path in paths:
        try:
            found = source.read(path)
        except Exception:
            continue
        if found is not None:
            texts[path] = found.lines
    return texts


def _module_evidence(path: str, line: int, texts: dict[str, tuple[str, ...]]) -> Evidence | None:
    lines = texts.get(path)
    if lines is None:
        return None
    return build_security_evidence(
        path=path, focus_start_line=line, focus_end_line=line, lines=list(lines)
    )


def _module_location(path: str, line: int) -> SourceLocation:
    return SourceLocation(
        file_path=path, start_line=line, start_column=0, end_line=line, end_column=0
    )


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            item.location.file_path,
            item.location.start_line,
            item.location.start_column,
            item.rule_id,
            item.identity_key,
        ),
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in _sort_findings(findings):
        if finding.identity_key in seen:
            continue
        seen.add(finding.identity_key)
        unique.append(finding)
    return unique


def _base_limitations(
    rule_id: str, prepared: PreparedAnalysis, extra: list[Limitation] | None = None
) -> list[Limitation]:
    limitations: list[Limitation] = []
    for reason in prepared.report.limitation_reasons:
        limitations.append(Limitation(scope=f"architecture:{rule_id}", reason=reason))
    limitations.extend(extra or [])
    return limitations


#: Presentation-only caps for inline neighbor listings in finding
#: descriptions. Metrics stay exact; only the displayed subset is bounded.
#: Both caps are deterministic (inputs are pre-sorted) and every truncation
#: carries an explicit "first N of M" statement plus a limitation-free,
#: self-describing sentence (the metric value itself remains exact).
MAX_LISTED_NEIGHBORS = 20
MAX_LISTED_SITES = 5


def _format_site_list(sites: list[str]) -> str:
    """Bounded `path:line` site list with an explicit remainder statement."""
    shown = sites[:MAX_LISTED_SITES]
    text = ", ".join(shown)
    if len(sites) > len(shown):
        text += f" (+{len(sites) - len(shown)} more)"
    return text


def _format_neighbor_block(items: list[str], noun: str) -> str:
    """Bounded bullet block stating displayed and true totals when cut."""
    if not items:
        return "none"
    shown = items[:MAX_LISTED_NEIGHBORS]
    text = "\n".join(f"- {item}" for item in shown)
    if len(items) > len(shown):
        text += f"\nShowing the first {len(shown)} of {len(items)} {noun}."
    return text


def _incomplete_note(prepared: PreparedAnalysis, path: str) -> Limitation | None:
    if path in prepared.partial_paths:
        return Limitation(
            scope="architecture:partial",
            reason=f"{path} is only partially represented; confidence reflects that.",
            path=path,
        )
    if path in prepared.unresolved_paths:
        return Limitation(
            scope="architecture:unresolved",
            reason=f"{path} has references that could not be resolved; related "
            "metrics are potentially incomplete.",
            path=path,
        )
    return None


# --- Rule executors ---------------------------------------------------------


def execute_circular_dependency(
    execution_context: RuleExecutionContext, prepared: PreparedAnalysis
) -> RuleOutcome:
    """ARCH-CIRCULAR-DEPENDENCY: existence-based, one finding per group."""
    context = execution_context.context
    report = prepared.report
    groups = cycle_analysis.find_cycles(report.graph)
    findings: list[Finding] = []
    for group in groups:
        if group.self_loop:
            location_path = group.members[0]
            title = f"Circular dependency detected: {location_path} depends on itself"
            description = (
                f"Module {location_path} statically imports itself. A self-dependency "
                "forms a trivial closed path. A circular dependency may indicate "
                "structural coupling or architectural complexity requiring review. "
                "It is a structural observation and does not assert a defect."
            )
            severity = Severity.LOW
            subject = f"cycle:self:{location_path}"
        else:
            location_path = group.members[0]
            member_lines = "\n".join(f"- {member}" for member in group.members)
            path_lines = " -> ".join(group.path)
            edge_lines: list[str] = []
            conditional = False
            for step in range(len(group.path) - 1):
                edge = report.graph.edges.get((group.path[step], group.path[step + 1]))
                if edge is None:
                    continue
                conditional = conditional or edge.conditional or edge.deferred
                sites = ", ".join(f"{path}:{line}" for path, line, _column in edge.locations)
                edge_lines.append(f"- {edge.source} -> {edge.target} ({sites})")
            parents = {
                member.rsplit("/", 1)[0] if "/" in member else "" for member in group.members
            }
            crosses = len(parents) > 1
            description = (
                f"Modules {', '.join(group.members)} form a closed dependency path: "
                f"{path_lines}. Participating modules:\n{member_lines}\n"
                "Relationships on the path:\n" + "\n".join(edge_lines)
            )
            if crosses:
                description += "\nThe cycle crosses package boundaries."
            description += (
                "\nThe displayed path is representative; this finding does not "
                "enumerate every cycle within the component."
            )
            description += (
                "\nA circular dependency may indicate structural coupling or "
                "architectural complexity requiring review. It is a structural "
                "observation and does not assert a defect."
            )
            severity = Severity.MEDIUM if crosses else Severity.LOW
            title = f"Circular dependency detected: {', '.join(group.members)}"
            subject = f"cycle:{','.join(group.members)}"
            if conditional:
                description += (
                    "\nAt least one relationship on the path is conditional or "
                    "deferred; such cycles may be accepted design choices."
                )
        confidence = Confidence.HIGH
        factors = ("closed path built from resolved relationships",)
        if report.limited or (not group.self_loop and conditional):
            confidence = Confidence.MEDIUM
            factors = ("graph may be incomplete or a closing edge is conditional/deferred",)
        location = _module_location(location_path, 1)
        evidence = _module_evidence(location_path, 1, prepared.source_texts)
        rule_limitations: list[Limitation] = []
        if evidence is None:
            rule_limitations.append(
                Limitation(
                    scope=f"architecture:{CIRCULAR_DEPENDENCY_SPEC.rule_id}",
                    reason="Source excerpt was unavailable; the finding rests on the "
                    "graph relationships described above.",
                    path=location_path,
                    rule_id=CIRCULAR_DEPENDENCY_SPEC.rule_id,
                )
            )
        findings.append(
            create_finding(
                rule_id=CIRCULAR_DEPENDENCY_SPEC.rule_id,
                analyzer_id=ARCHITECTURE_ANALYZER_ID,
                category="architecture",
                title=title,
                description=description,
                severity=severity,
                confidence=confidence,
                location=location,
                evidence=evidence,
                recommendation=CIRCULAR_DEPENDENCY_SPEC.recommendation,
                limitations=tuple(rule_limitations),
                analyzer_version=context.analyzer_version,
                rule_set_version=context.rule_set_version,
                severity_factors=(f"crosses package boundary: {crosses}",)
                if not group.self_loop
                else ("self-dependency",),
                confidence_factors=factors,
                analysis_id=context.analysis_id,
                subject_key=subject,
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(CIRCULAR_DEPENDENCY_SPEC.rule_id, prepared),
    )


def _threshold_rule_outcome(
    *,
    execution_context: RuleExecutionContext,
    prepared: PreparedAnalysis,
    spec: ArchitectureRuleSpec,
    subject: str,
    location_path: str,
    location_line: int,
    title: str,
    description: str,
    value: int,
    threshold: int,
    threshold_name: str,
    extra_relationships: str = "",
    incomplete: bool = False,
) -> Finding:
    context = execution_context.context
    severity = Severity.MEDIUM if value >= 2 * threshold else Severity.LOW
    confidence = Confidence.MEDIUM if incomplete else Confidence.HIGH
    evidence = _module_evidence(location_path, location_line, prepared.source_texts)
    rule_limitations: list[Limitation] = []
    note = _incomplete_note(prepared, location_path)
    if note is not None:
        rule_limitations.append(note)
    if evidence is None:
        rule_limitations.append(
            Limitation(
                scope=f"architecture:{spec.rule_id}",
                reason="Source excerpt was unavailable; the finding rests on the "
                "metric and relationships described above.",
                path=location_path,
                rule_id=spec.rule_id,
            )
        )
    full_description = (
        f"{description}\nMetric value: {value}; threshold applied: "
        f"{threshold_name} > {threshold} (strict).{extra_relationships}"
    )
    return create_finding(
        rule_id=spec.rule_id,
        analyzer_id=ARCHITECTURE_ANALYZER_ID,
        category="architecture",
        title=title,
        description=full_description,
        severity=severity,
        confidence=confidence,
        location=_module_location(location_path, location_line),
        evidence=evidence,
        recommendation=spec.recommendation,
        limitations=tuple(rule_limitations),
        analyzer_version=context.analyzer_version,
        rule_set_version=context.rule_set_version,
        applied_thresholds=((threshold_name, threshold),),
        severity_factors=(f"value {value} against threshold {threshold}",),
        confidence_factors=("measurement may be incomplete",) if incomplete else ("direct count",),
        analysis_id=context.analysis_id,
        subject_key=subject,
    )


def execute_high_fan_out(
    execution_context: RuleExecutionContext, prepared: PreparedAnalysis
) -> RuleOutcome:
    """ARCH-HIGH-FAN-OUT: one finding per module strictly above threshold."""
    context = execution_context.context
    threshold = context.thresholds.fan_out
    findings: list[Finding] = []
    for path in sorted(prepared.report.graph.nodes):
        metric = fan_out(prepared.report.graph, path)
        assert metric.value is not None
        if metric.value <= threshold:
            continue
        neighbors = prepared.report.graph.successors(path)
        lines = []
        for target in neighbors:
            edge = prepared.report.graph.edges[(path, target)]
            sites = _format_site_list([f"{path_}:{line}" for path_, line, _c in edge.locations])
            lines.append(f"- {target} ({sites})")
        incomplete = path in prepared.partial_paths or path in prepared.unresolved_paths
        findings.append(
            _threshold_rule_outcome(
                execution_context=execution_context,
                prepared=prepared,
                spec=HIGH_FAN_OUT_SPEC,
                subject=f"fan-out:{path}",
                location_path=path,
                location_line=1,
                title=f"Potentially high fan-out: {path}",
                description=(
                    f"Module {path} depends on {metric.value} distinct internal "
                    "modules. Outgoing relationships:\n"
                    + _format_neighbor_block(lines, "outgoing neighbors")
                ),
                value=metric.value,
                threshold=threshold,
                threshold_name="fan_out",
                incomplete=incomplete or prepared.report.limited,
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(HIGH_FAN_OUT_SPEC.rule_id, prepared),
    )


def execute_high_fan_in(
    execution_context: RuleExecutionContext, prepared: PreparedAnalysis
) -> RuleOutcome:
    """ARCH-HIGH-FAN-IN: one finding per module strictly above threshold."""
    context = execution_context.context
    threshold = context.thresholds.fan_in
    findings: list[Finding] = []
    for path in sorted(prepared.report.graph.nodes):
        metric = fan_in(prepared.report.graph, path)
        assert metric.value is not None
        if metric.value <= threshold:
            continue
        neighbors = prepared.report.graph.predecessors(path)
        lines = []
        for source in neighbors:
            edge = prepared.report.graph.edges[(source, path)]
            sites = _format_site_list([f"{path_}:{line}" for path_, line, _c in edge.locations])
            lines.append(f"- {source} ({sites})")
        incomplete = path in prepared.partial_paths or path in prepared.unresolved_paths
        findings.append(
            _threshold_rule_outcome(
                execution_context=execution_context,
                prepared=prepared,
                spec=HIGH_FAN_IN_SPEC,
                subject=f"fan-in:{path}",
                location_path=path,
                location_line=1,
                title=f"Potentially high fan-in: {path}",
                description=(
                    f"Module {path} is depended on by {metric.value} distinct internal "
                    "modules. Incoming relationships:\n"
                    + _format_neighbor_block(lines, "incoming neighbors")
                ),
                value=metric.value,
                threshold=threshold,
                threshold_name="fan_in",
                incomplete=incomplete or prepared.report.limited,
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(HIGH_FAN_IN_SPEC.rule_id, prepared),
    )


def execute_high_coupling(
    execution_context: RuleExecutionContext, prepared: PreparedAnalysis
) -> RuleOutcome:
    """ARCH-HIGH-COUPLING: union degree strictly above threshold."""
    context = execution_context.context
    threshold = context.thresholds.coupling
    findings: list[Finding] = []
    for path in sorted(prepared.report.graph.nodes):
        metric = coupling_def_1(prepared.report.graph, path)
        assert metric.value is not None
        if metric.value <= threshold:
            continue
        incoming = prepared.report.graph.predecessors(path)
        outgoing = prepared.report.graph.successors(path)
        incomplete = path in prepared.partial_paths or path in prepared.unresolved_paths
        incoming_block = _format_neighbor_block(list(incoming), "incoming neighbors")
        outgoing_block = _format_neighbor_block(list(outgoing), "outgoing neighbors")
        findings.append(
            _threshold_rule_outcome(
                execution_context=execution_context,
                prepared=prepared,
                spec=HIGH_COUPLING_SPEC,
                subject=f"coupling:{path}",
                location_path=path,
                location_line=1,
                title=f"Elevated coupling: {path}",
                description=(
                    f"Module {path} has coupling-def-1 {metric.value} "
                    f"(|In union Out| over internal edges). Incoming "
                    f"({len(incoming)}):\n{incoming_block}\n"
                    f"Outgoing ({len(outgoing)}):\n{outgoing_block}"
                ),
                value=metric.value,
                threshold=threshold,
                threshold_name="coupling",
                extra_relationships=" Definition: coupling-def-1(M) = |In(M) union Out(M)|.",
                incomplete=incomplete or prepared.report.limited,
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(HIGH_COUPLING_SPEC.rule_id, prepared),
    )


def execute_large_module(
    execution_context: RuleExecutionContext, prepared: PreparedAnalysis
) -> RuleOutcome:
    """ARCH-LARGE-MODULE: lines > 500 OR declarations > 30 (either signal)."""
    context = execution_context.context
    lines_threshold = context.thresholds.module_lines
    decl_threshold = context.thresholds.module_declarations
    findings: list[Finding] = []
    for path in sorted(prepared.report.graph.nodes):
        module = prepared.modules.get(path)
        if module is None:
            continue
        lines = module_line_count(module, prepared.source_texts.get(path))
        declarations = module_declaration_count(module)
        fired: list[str] = []
        if lines is not None and lines > lines_threshold:
            fired.append(f"lines_of_code {lines} > {lines_threshold}")
        if declarations > decl_threshold:
            fired.append(f"declaration_count {declarations} > {decl_threshold}")
        if not fired:
            continue
        incomplete = (
            path in prepared.partial_paths
            or (lines is None)
            or prepared.source_texts.get(path) is None
        )
        severity = Severity.MEDIUM if len(fired) >= 2 else Severity.LOW
        evidence = _module_evidence(path, 1, prepared.source_texts)
        rule_limitations: list[Limitation] = []
        note = _incomplete_note(prepared, path)
        if note is not None:
            rule_limitations.append(note)
        if prepared.source_texts.get(path) is None:
            rule_limitations.append(
                Limitation(
                    scope=f"architecture:{LARGE_MODULE_SPEC.rule_id}",
                    reason="Source lines were unavailable; the line count rests on "
                    "NCM locations and may understate trailing content.",
                    path=path,
                    rule_id=LARGE_MODULE_SPEC.rule_id,
                )
            )
        if evidence is None:
            rule_limitations.append(
                Limitation(
                    scope=f"architecture:{LARGE_MODULE_SPEC.rule_id}",
                    reason="Source excerpt was unavailable.",
                    path=path,
                    rule_id=LARGE_MODULE_SPEC.rule_id,
                )
            )
        findings.append(
            create_finding(
                rule_id=LARGE_MODULE_SPEC.rule_id,
                analyzer_id=ARCHITECTURE_ANALYZER_ID,
                category="architecture",
                title=f"Large module: {path}",
                description=(
                    f"Module {path} exceeds a large-module size signal: "
                    f"{'; '.join(fired)}. Evaluated signals: lines_of_code "
                    f"({lines if lines is not None else 'unknown'}), "
                    f"declaration_count ({declarations}). Size may make "
                    "understanding and maintenance more difficult; it is not "
                    "evidence of poor architecture."
                ),
                severity=severity,
                confidence=Confidence.MEDIUM if incomplete else Confidence.HIGH,
                location=_module_location(path, 1),
                evidence=evidence,
                recommendation=LARGE_MODULE_SPEC.recommendation,
                limitations=tuple(rule_limitations),
                analyzer_version=context.analyzer_version,
                rule_set_version=context.rule_set_version,
                applied_thresholds=(
                    ("module_lines", lines_threshold),
                    ("module_declarations", decl_threshold),
                ),
                severity_factors=(f"{len(fired)} signal(s) exceeded",),
                confidence_factors=(
                    ("measurement may be incomplete",) if incomplete else ("direct measurement",)
                ),
                analysis_id=context.analysis_id,
                subject_key=f"large-module:{path}",
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(LARGE_MODULE_SPEC.rule_id, prepared)
        + [
            Limitation(
                scope=f"architecture:{LARGE_MODULE_SPEC.rule_id}",
                reason="Generated files cannot be identified from NCM alone; sizes "
                "include generated content where present.",
            )
        ],
    )


def execute_large_class(
    execution_context: RuleExecutionContext, prepared: PreparedAnalysis
) -> RuleOutcome:
    """ARCH-LARGE-CLASS: class lines > 200 OR methods > 10 (either signal)."""
    context = execution_context.context
    lines_threshold = context.thresholds.class_lines
    methods_threshold = context.thresholds.class_methods
    findings: list[Finding] = []
    for path in sorted(prepared.modules):
        module = prepared.modules[path]
        for cls in sorted(module.classes, key=lambda item: item.qualified_name):
            lines = class_line_count(cls)
            methods = class_method_count(module, cls)
            fired: list[str] = []
            if lines is not None and lines > lines_threshold:
                fired.append(f"class lines {lines} > {lines_threshold}")
            if methods > methods_threshold:
                fired.append(f"method_count {methods} > {methods_threshold}")
            if not fired:
                continue
            incomplete = path in prepared.partial_paths
            severity = Severity.MEDIUM if len(fired) >= 2 else Severity.LOW
            line = cls.location.start_line
            evidence = _module_evidence(path, line, prepared.source_texts)
            rule_limitations: list[Limitation] = []
            note = _incomplete_note(prepared, path)
            if note is not None:
                rule_limitations.append(note)
            if evidence is None:
                rule_limitations.append(
                    Limitation(
                        scope=f"architecture:{LARGE_CLASS_SPEC.rule_id}",
                        reason="Source excerpt was unavailable.",
                        path=path,
                        rule_id=LARGE_CLASS_SPEC.rule_id,
                    )
                )
            findings.append(
                create_finding(
                    rule_id=LARGE_CLASS_SPEC.rule_id,
                    analyzer_id=ARCHITECTURE_ANALYZER_ID,
                    category="architecture",
                    title=f"Large class: {cls.qualified_name}",
                    description=(
                        f"Class {cls.qualified_name} in {path} exceeds a large-class "
                        f"signal: {'; '.join(fired)}. A large class is not claimed "
                        "to violate a design principle."
                    ),
                    severity=severity,
                    confidence=Confidence.MEDIUM if incomplete else Confidence.HIGH,
                    location=_module_location(path, line),
                    evidence=evidence,
                    recommendation=LARGE_CLASS_SPEC.recommendation,
                    limitations=tuple(rule_limitations),
                    analyzer_version=context.analyzer_version,
                    rule_set_version=context.rule_set_version,
                    applied_thresholds=(
                        ("class_lines", lines_threshold),
                        ("class_methods", methods_threshold),
                    ),
                    severity_factors=(f"{len(fired)} signal(s) exceeded",),
                    confidence_factors=(
                        ("measurement may be incomplete",)
                        if incomplete
                        else ("direct measurement",)
                    ),
                    analysis_id=context.analysis_id,
                    subject_key=f"large-class:{path}:{cls.qualified_name}",
                )
            )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(LARGE_CLASS_SPEC.rule_id, prepared),
    )


def execute_large_function(
    execution_context: RuleExecutionContext, prepared: PreparedAnalysis
) -> RuleOutcome:
    """ARCH-LARGE-FUNCTION: lines > 50 OR complexity > 10 (either signal)."""
    context = execution_context.context
    lines_threshold = context.thresholds.function_lines
    complexity_threshold = context.thresholds.function_complexity
    findings: list[Finding] = []
    for path in sorted(prepared.modules):
        module = prepared.modules[path]
        for fun in sorted(module.functions, key=lambda item: item.qualified_name):
            lines = function_line_count(fun)
            complexity = function_complexity_lower_bound(module, fun)
            assert complexity.value is not None
            fired: list[str] = []
            if lines is not None and lines > lines_threshold:
                fired.append(f"function lines {lines} > {lines_threshold}")
            if complexity.value > complexity_threshold:
                fired.append(
                    f"complexity {complexity.value} > {complexity_threshold} "
                    "(NCM lower bound; true value is at least this)"
                )
            if not fired:
                continue
            complexity_only = len(fired) == 1 and fired[0].startswith("complexity")
            incomplete = path in prepared.partial_paths or complexity_only
            severity = Severity.MEDIUM if len(fired) >= 2 else Severity.LOW
            line = fun.location.start_line
            evidence = _module_evidence(path, line, prepared.source_texts)
            rule_limitations: list[Limitation] = []
            note = _incomplete_note(prepared, path)
            if note is not None:
                rule_limitations.append(note)
            if complexity_only:
                rule_limitations.append(
                    Limitation(
                        scope=f"architecture:{LARGE_FUNCTION_SPEC.rule_id}",
                        reason="Complexity here is an NCM lower bound (boolean operators, "
                        "ternaries, comprehensions, and asserts are not represented); "
                        "confidence reflects that.",
                        path=path,
                        rule_id=LARGE_FUNCTION_SPEC.rule_id,
                    )
                )
            if evidence is None:
                rule_limitations.append(
                    Limitation(
                        scope=f"architecture:{LARGE_FUNCTION_SPEC.rule_id}",
                        reason="Source excerpt was unavailable.",
                        path=path,
                        rule_id=LARGE_FUNCTION_SPEC.rule_id,
                    )
                )
            findings.append(
                create_finding(
                    rule_id=LARGE_FUNCTION_SPEC.rule_id,
                    analyzer_id=ARCHITECTURE_ANALYZER_ID,
                    category="architecture",
                    title=f"Large function: {fun.qualified_name}",
                    description=(
                        f"Function {fun.qualified_name} in module {path} exceeds a "
                        f"large-function signal: {'; '.join(fired)}. Architecturally, "
                        "the function is a large, concentrated unit within the module "
                        "and repository structure."
                    ),
                    severity=severity,
                    confidence=Confidence.MEDIUM if incomplete else Confidence.HIGH,
                    location=_module_location(path, line),
                    evidence=evidence,
                    recommendation=LARGE_FUNCTION_SPEC.recommendation,
                    limitations=tuple(rule_limitations),
                    analyzer_version=context.analyzer_version,
                    rule_set_version=context.rule_set_version,
                    applied_thresholds=(
                        ("function_lines", lines_threshold),
                        ("function_complexity", complexity_threshold),
                    ),
                    severity_factors=(f"{len(fired)} signal(s) exceeded",),
                    confidence_factors=(
                        ("measurement may be incomplete",)
                        if incomplete
                        else ("direct measurement",)
                    ),
                    analysis_id=context.analysis_id,
                    subject_key=f"large-function:{path}:{fun.qualified_name}",
                )
            )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(LARGE_FUNCTION_SPEC.rule_id, prepared),
    )


def execute_layer_violation(
    execution_context: RuleExecutionContext, prepared: PreparedAnalysis
) -> RuleOutcome:
    """ARCH-LAYER-VIOLATION: one finding per upward relationship."""
    context = execution_context.context
    assignments = infer_layers(sorted(prepared.report.graph.nodes))
    violations, identifiable = find_violations(prepared.report.graph, assignments)
    extra: list[Limitation] = []
    if not identifiable:
        extra.append(
            Limitation(
                scope=f"architecture:{LAYER_VIOLATION_SPEC.rule_id}",
                reason="Layer boundaries could not be identified with adequate evidence "
                "(fewer than two distinct layers); the rule was not evaluated and "
                "this is not a clean result.",
                rule_id=LAYER_VIOLATION_SPEC.rule_id,
            )
        )
        return RuleOutcome(
            findings=[],
            limitations=_base_limitations(LAYER_VIOLATION_SPEC.rule_id, prepared, extra),
        )
    consistent = sum(
        1
        for edge in prepared.report.graph.sorted_edges()
        if _edge_consistent(edge.source, edge.target, assignments)
    )
    findings: list[Finding] = []
    for violation in violations:
        edge = prepared.report.graph.edges.get((violation.source, violation.target))
        sites = (
            ", ".join(f"{path}:{line}" for path, line, _c in edge.locations)
            if edge is not None
            else "unknown"
        )
        from_filename = (
            assignments[violation.source].from_filename
            or assignments[violation.target].from_filename
        )
        confidence = Confidence.LOW if from_filename else Confidence.MEDIUM
        # Naming-inferred layers never escalate severity: the contract
        # authorizes considering directional consistency (docs/08 §6.8) but
        # defines no numeric mapping, so violations stay Low with the
        # consistency count recorded as a severity factor instead.
        severity = Severity.LOW
        line = edge.locations[0][1] if edge is not None and edge.locations else 1
        evidence = _module_evidence(violation.source, line, prepared.source_texts)
        rule_limitations: list[Limitation] = []
        if evidence is None:
            rule_limitations.append(
                Limitation(
                    scope=f"architecture:{LAYER_VIOLATION_SPEC.rule_id}",
                    reason="Source excerpt was unavailable.",
                    path=violation.source,
                    rule_id=LAYER_VIOLATION_SPEC.rule_id,
                )
            )
        findings.append(
            create_finding(
                rule_id=LAYER_VIOLATION_SPEC.rule_id,
                analyzer_id=ARCHITECTURE_ANALYZER_ID,
                category="architecture",
                title=(
                    f"Possible layer violation: {violation.source} "
                    f"({violation.source_layer}) -> {violation.target} "
                    f"({violation.target_layer})"
                ),
                description=(
                    f"Dependency {violation.source} [{violation.source_layer}] -> "
                    f"{violation.target} [{violation.target_layer}] runs counter to "
                    "the identified downward layering direction. Layer evidence: "
                    f"{violation.source}: {violation.source_evidence}; "
                    f"{violation.target}: {violation.target_evidence}. Establishing "
                    f"statement(s): {sites}. Layers are inferred observations for "
                    "interpretation, not a pass or fail judgment."
                ),
                severity=severity,
                confidence=confidence,
                location=_module_location(violation.source, line),
                evidence=evidence,
                recommendation=LAYER_VIOLATION_SPEC.recommendation,
                limitations=tuple(rule_limitations),
                analyzer_version=context.analyzer_version,
                rule_set_version=context.rule_set_version,
                severity_factors=(f"{consistent} consistent edge(s) elsewhere",),
                confidence_factors=("filename-based layer evidence",)
                if from_filename
                else ("directory-based layer evidence",),
                analysis_id=context.analysis_id,
                subject_key=f"layer:{violation.source}>{violation.target}",
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(LAYER_VIOLATION_SPEC.rule_id, prepared, extra),
    )


def _edge_consistent(source: str, target: str, assignments: dict[str, LayerAssignment]) -> bool:
    source_item = assignments.get(source)
    target_item = assignments.get(target)
    if source_item is None or target_item is None:
        return False
    if source_item.layer == UNKNOWN or target_item.layer == UNKNOWN:
        return False
    return LAYER_RANK[source_item.layer] <= LAYER_RANK[target_item.layer]


def execute_multiple_responsibility(
    execution_context: RuleExecutionContext, prepared: PreparedAnalysis
) -> RuleOutcome:
    """ARCH-MULTIPLE-RESPONSIBILITY: multi-category candidates only."""
    context = execution_context.context
    thresholds = context.thresholds
    findings: list[Finding] = []
    for path in sorted(prepared.report.graph.nodes):
        module = prepared.modules.get(path)
        if module is None:
            continue
        lines_threshold = thresholds.module_lines
        decl_threshold = thresholds.module_declarations
        lines = module_line_count(module, prepared.source_texts.get(path))
        large_module = (lines is not None and lines > lines_threshold) or (
            module_declaration_count(module) > decl_threshold
        )
        large_classes = tuple(
            cls.qualified_name
            for cls in module.classes
            if (class_line_count(cls) or 0) > thresholds.class_lines
            or class_method_count(module, cls) > thresholds.class_methods
        )
        large_functions: list[tuple[str, int | None]] = []
        complex_functions: list[tuple[str, int | None]] = []
        for fun in module.functions:
            fun_lines = function_line_count(fun)
            complexity = function_complexity_lower_bound(module, fun)
            assert complexity.value is not None
            if fun_lines is not None and fun_lines > thresholds.function_lines:
                large_functions.append((fun.qualified_name, fun_lines))
            if complexity.value > thresholds.function_complexity:
                complex_functions.append((fun.qualified_name, complexity.value))
        fan_out_value = fan_out(prepared.report.graph, path).value
        coupling_value = coupling_def_1(prepared.report.graph, path).value
        signals = collect_signals(
            module_path=path,
            module=module,
            fan_out_value=fan_out_value,
            coupling_value=coupling_value,
            large_module=large_module,
            large_class_names=large_classes,
            large_functions=tuple(large_functions),
            complex_functions=tuple(complex_functions),
            thresholds=thresholds,
        )
        if not is_candidate(signals):
            continue
        candidate = build_candidate(path, signals)
        signal_lines = "\n".join(
            f"- [{signal.category}] {signal.description}" for signal in candidate.signals
        )
        evidence = _module_evidence(path, 1, prepared.source_texts)
        rule_limitations: list[Limitation] = []
        note = _incomplete_note(prepared, path)
        if note is not None:
            rule_limitations.append(note)
        if evidence is None:
            rule_limitations.append(
                Limitation(
                    scope=f"architecture:{MULTIPLE_RESPONSIBILITY_SPEC.rule_id}",
                    reason="Source excerpt was unavailable.",
                    path=path,
                    rule_id=MULTIPLE_RESPONSIBILITY_SPEC.rule_id,
                )
            )
        findings.append(
            create_finding(
                rule_id=MULTIPLE_RESPONSIBILITY_SPEC.rule_id,
                analyzer_id=ARCHITECTURE_ANALYZER_ID,
                category="architecture",
                title=f"Potential multiple-responsibility signal: {path}",
                description=(
                    f"Module {path} shows structural signals from "
                    f"{len(candidate.categories)} categories "
                    f"({', '.join(candidate.categories)}); "
                    f"{graph_context_for_candidate(prepared.report.graph, path)}. "
                    f"Contributing signals:\n{signal_lines}\nSignals were combined "
                    "by category count (more than one category required). This is a "
                    "potential structure requiring contextual review, not proof of a "
                    "design violation."
                ),
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                location=_module_location(path, 1),
                evidence=evidence,
                recommendation=MULTIPLE_RESPONSIBILITY_SPEC.recommendation,
                limitations=tuple(rule_limitations),
                analyzer_version=context.analyzer_version,
                rule_set_version=context.rule_set_version,
                severity_factors=(f"{len(candidate.categories)} signal categories",),
                confidence_factors=("responsibility boundaries not reliably inferable",),
                analysis_id=context.analysis_id,
                subject_key=f"responsibility:{path}",
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(MULTIPLE_RESPONSIBILITY_SPEC.rule_id, prepared),
    )


# --- Analyzer -----------------------------------------------------------------


def _bind(spec: ArchitectureRuleSpec, analyzer: ArchitectureAnalyzer, kind: str) -> RegisteredRule:
    """Bind a rule implementation to metadata plus analyzer-owned inputs."""

    def execute(execution_context: RuleExecutionContext) -> RuleOutcome:
        prepared = analyzer.prepared_for(execution_context.context)
        if kind == "circular":
            return execute_circular_dependency(execution_context, prepared)
        if kind == "fan-out":
            return execute_high_fan_out(execution_context, prepared)
        if kind == "fan-in":
            return execute_high_fan_in(execution_context, prepared)
        if kind == "coupling":
            return execute_high_coupling(execution_context, prepared)
        if kind == "large-module":
            return execute_large_module(execution_context, prepared)
        if kind == "large-class":
            return execute_large_class(execution_context, prepared)
        if kind == "large-function":
            return execute_large_function(execution_context, prepared)
        if kind == "layer":
            return execute_layer_violation(execution_context, prepared)
        return execute_multiple_responsibility(execution_context, prepared)

    metadata = RuleMetadata(
        rule_id=spec.rule_id,
        name=spec.name,
        description=spec.description,
        analyzer_id=ARCHITECTURE_ANALYZER_ID,
        version=ARCHITECTURE_ANALYZER_VERSION,
        default_severity=spec.default_severity,
        documentation_ref=spec.documentation_ref,
    )
    return RegisteredRule(metadata=metadata, execute=execute)


def build_architecture_rules(analyzer: ArchitectureAnalyzer) -> list[RegisteredRule]:
    """Build the registered architecture rules (deterministic rule-ID order)."""
    bound = [
        _bind(CIRCULAR_DEPENDENCY_SPEC, analyzer, "circular"),
        _bind(HIGH_FAN_OUT_SPEC, analyzer, "fan-out"),
        _bind(HIGH_FAN_IN_SPEC, analyzer, "fan-in"),
        _bind(HIGH_COUPLING_SPEC, analyzer, "coupling"),
        _bind(LARGE_MODULE_SPEC, analyzer, "large-module"),
        _bind(LARGE_CLASS_SPEC, analyzer, "large-class"),
        _bind(LARGE_FUNCTION_SPEC, analyzer, "large-function"),
        _bind(LAYER_VIOLATION_SPEC, analyzer, "layer"),
        _bind(MULTIPLE_RESPONSIBILITY_SPEC, analyzer, "responsibility"),
    ]
    return sorted(bound, key=lambda rule: rule.metadata.rule_id)


class ArchitectureAnalyzer(Analyzer):
    """Static architecture analyzer over NCM plus bounded source excerpts."""

    id = ARCHITECTURE_ANALYZER_ID
    name = "Architecture Analyzer"
    version = ARCHITECTURE_ANALYZER_VERSION

    def __init__(self, source: SourceProvider | None = None) -> None:
        self._source = source
        self._prepared_cache: dict[str, PreparedAnalysis] = {}

    def prepared_for(self, context: object) -> PreparedAnalysis:
        """Graph, modules, and source lines for an analysis (cached per ID)."""
        analysis_id = getattr(context, "analysis_id", "-")
        cached = self._prepared_cache.get(analysis_id)
        if cached is not None:
            return cached
        ncm = getattr(context, "ncm", None)
        if ncm is None:
            from app.ncm import NcmRepository as _NcmRepository

            ncm = _NcmRepository(analysis_id=analysis_id)
        report = build_graph(ncm)
        modules = {
            entry.path: entry.module
            for entry in ncm.files
            if entry.module is not None and (entry.language or "").lower() == "python"
        }
        texts = _read_sources(self._source, sorted(report.graph.nodes))
        prepared = PreparedAnalysis(
            report=report,
            modules=modules,
            source_texts=texts,
            partial_paths=set(report.partial_modules),
            unresolved_paths={item.path for item in report.unresolved},
        )
        self._prepared_cache[analysis_id] = prepared
        log_event(
            _logger,
            logging.INFO,
            "architecture.prepared",
            "Architecture analysis inputs prepared",
            analysis_id=analysis_id,
            modules=len(report.graph.nodes),
            edges=len(report.graph.edges),
        )
        return prepared

    def rules(self) -> list[RegisteredRule]:
        """Only the registered V1.0 architecture rules (never other domains)."""
        return build_architecture_rules(self)

    def coverage(self, ncm: NcmRepository) -> list[Coverage]:
        """Explicit per-rule coverage for an NCM snapshot (never clean)."""
        from app.analyzers.architecture.modules import SUPPORTED_LANGUAGE

        report = build_graph(ncm)
        python_paths = [
            entry.path
            for entry in ncm.files
            if entry.module is not None and (entry.language or "").lower() == SUPPORTED_LANGUAGE
        ]
        rows: list[Coverage] = []
        for spec in ARCHITECTURE_RULE_SPECS:
            if not python_paths:
                rows.append(
                    Coverage(
                        rule_id=spec.rule_id,
                        status=CoverageStatus.UNSUPPORTED,
                        reason="No supported-language (python) content in scope.",
                    )
                )
            elif spec.rule_id == "ARCH-LAYER-VIOLATION":
                assignments = infer_layers(sorted(report.graph.nodes))
                _, identifiable = find_violations(report.graph, assignments)
                if not identifiable:
                    rows.append(
                        Coverage(
                            rule_id=spec.rule_id,
                            status=CoverageStatus.NOT_APPLICABLE,
                            reason="Layer boundaries could not be identified; "
                            "the rule was not evaluated.",
                        )
                    )
                elif report.limited:
                    rows.append(
                        Coverage(
                            rule_id=spec.rule_id,
                            status=CoverageStatus.PARTIALLY_COVERED,
                            reason="Layers identified but extraction is incomplete.",
                        )
                    )
                else:
                    rows.append(
                        Coverage(
                            rule_id=spec.rule_id,
                            status=CoverageStatus.COVERED,
                            reason="Layer assignments evaluated against graph edges.",
                        )
                    )
            elif report.limited:
                rows.append(
                    Coverage(
                        rule_id=spec.rule_id,
                        status=CoverageStatus.PARTIALLY_COVERED,
                        reason="Extraction incomplete (failed/partial files or "
                        "truncated graph); metrics may be understated.",
                    )
                )
            else:
                rows.append(
                    Coverage(
                        rule_id=spec.rule_id,
                        status=CoverageStatus.COVERED,
                        reason="Applicable modules analyzed with a sufficient representation.",
                    )
                )
        log_event(
            _logger,
            logging.INFO,
            "architecture.coverage.computed",
            "Architecture coverage computed",
            coverage={item.rule_id: item.status.value for item in rows},
        )
        return rows


__all__ = [
    "ArchitectureAnalyzer",
    "build_architecture_rules",
]
