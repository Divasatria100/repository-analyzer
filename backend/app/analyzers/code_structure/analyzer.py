"""Code-structure analyzer execution pipeline (Phase 10, TASK-139–144).

The ``code_structure`` analyzer runs the four registered V1.0 rules
(docs/10 §5.14A CODE-REQ-001–006) through the existing Phase 6 machinery:

* identity via :class:`app.analyzers.base.Analyzer` (``id = "code_structure"``),
* deterministic rule-ID order, per-rule failure isolation (inherited),
* findings through the common Finding model only (no parallel model).

Inputs are the NCM plus an optional narrow ``SourceProvider`` for bounded
read-as-data excerpts and duplicate body tokenization (injected like the
sibling analyzers; the context itself never carries I/O or network). No
second parser, no ``ast``/``tree_sitter``/``app.parsers.*`` imports, no
execution, no network. Severity/confidence follow CODE-REQ-001–004
exactly; hotspots order review without scoring.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app.analyzers.base import Analyzer
from app.analyzers.code_structure import duplicates as duplicate_analysis
from app.analyzers.code_structure.hotspots import HotspotInput, build_hotspots
from app.analyzers.code_structure.measurements import (
    mccabe_complexity,
    nesting_depth,
    parameter_count,
)
from app.analyzers.code_structure.metadata import (
    CODE_ANALYZER_ID,
    CODE_ANALYZER_VERSION,
    CODE_RULE_SPECS,
    DEEP_NESTING_SPEC,
    DUPLICATE_CANDIDATE_SPEC,
    HIGH_COMPLEXITY_SPEC,
    HIGH_PARAMETER_COUNT_SPEC,
    CodeRuleSpec,
)
from app.analyzers.code_structure.models import (
    CodeReport,
    DuplicateGroup,
    FunctionMeasurement,
    Hotspot,
)
from app.analyzers.code_structure.tokens import (
    body_text,
    is_trivial_sequence,
    normalize_body_tokens,
)
from app.analyzers.context import AnalysisContext
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

_logger = get_logger("analyzers.code_structure")

#: Standing coverage note for complexity: the NCM decision set is a lower
#: bound of true McCabe complexity (CODE-REQ-001 lists constructs NCM does
#: not represent). Attached to the complexity outcome whenever functions
#: were measured, and to complexity-only findings via confidence handling.
COMPLEXITY_COVERAGE_NOTE = (
    "McCabe values rest on NCM control-flow nodes (if/elif, for/while, except "
    "handlers); boolean operators, ternary expressions, comprehensions with "
    "conditions, and asserts are not represented in NCM, so values are lower "
    "bounds and missed exceedances are possible."
)


@dataclass
class PreparedCode:
    """Shared per-analysis inputs built once and reused by every rule."""

    modules: dict[str, NormalizedModule]
    source_texts: dict[str, tuple[str, ...]]
    measurements: dict[tuple[str, str], dict[str, FunctionMeasurement]]
    duplicate_report: CodeReport
    duplicate_groups: list[DuplicateGroup]
    failed_files: tuple[str, ...] = ()
    unsupported_files: tuple[str, ...] = ()
    partial_modules: tuple[str, ...] = ()
    python_paths: tuple[str, ...] = ()
    limitation_reasons: tuple[str, ...] = field(default_factory=tuple)


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


def _function_evidence(path: str, line: int, texts: dict[str, tuple[str, ...]]) -> Evidence | None:
    lines = texts.get(path)
    if lines is None:
        return None
    return build_security_evidence(
        path=path, focus_start_line=line, focus_end_line=line, lines=list(lines)
    )


def _function_location(path: str, line: int) -> SourceLocation:
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
    rule_id: str, prepared: PreparedCode, extra: list[Limitation] | None = None
) -> list[Limitation]:
    limitations = [
        Limitation(scope=f"code_structure:{rule_id}", reason=reason)
        for reason in prepared.limitation_reasons
    ]
    limitations.extend(extra or [])
    return limitations


def _partial_note(prepared: PreparedCode, path: str) -> Limitation | None:
    if path in set(prepared.partial_modules):
        return Limitation(
            scope="code_structure:partial",
            reason=f"{path} is only partially represented; measurements rest on "
            "the represented portion.",
            path=path,
        )
    return None


def _scan_ncm(
    ncm: NcmRepository,
) -> tuple[
    dict[str, NormalizedModule], tuple[str, ...], tuple[str, ...], tuple[str, ...], list[str]
]:
    """Collect python modules plus file-state diagnostics (deterministic)."""
    modules: dict[str, NormalizedModule] = {}
    failed: list[str] = []
    unsupported: list[str] = []
    partial: list[str] = []
    reasons: list[str] = []
    for entry in sorted(ncm.files, key=lambda item: item.path):
        language = (entry.language or "").lower()
        if entry.module is None or language != "python":
            if entry.parse_state == "failed":
                failed.append(entry.path)
                reasons.append(f"{entry.path}: file failed to parse; not measured")
            elif entry.parse_state == "unsupported" or language != "python":
                unsupported.append(entry.path)
                reasons.append(
                    f"{entry.path}: unsupported for code-structure analysis; not treated as clean"
                )
            else:
                reasons.append(f"{entry.path}: skipped; not treated as clean")
            continue
        modules[entry.path] = entry.module
        if entry.module.completeness != "fully":
            partial.append(entry.path)
            reasons.append(f"{entry.path}: module is only partially represented")
    return modules, tuple(failed), tuple(unsupported), tuple(partial), reasons


def _measure_all(
    modules: dict[str, NormalizedModule],
) -> dict[tuple[str, str], dict[str, FunctionMeasurement]]:
    """Per-function measurements, keyed by (path, function id)."""
    measured: dict[tuple[str, str], dict[str, FunctionMeasurement]] = {}
    for path in sorted(modules):
        module = modules[path]
        for fun in sorted(
            module.functions, key=lambda item: (item.location.start_line, item.qualified_name)
        ):
            complexity = mccabe_complexity(module, fun)
            nesting = nesting_depth(module, fun)
            params = parameter_count(path, fun)
            measured[(path, fun.id)] = {
                "complexity": complexity.measurement,
                "nesting_depth": nesting.measurement,
                "parameter_count": params,
            }
    return measured


def _local_names(module: NormalizedModule, fun_id: str) -> frozenset[str]:
    """Identifier names positively identified as function-local from NCM.

    Parameters plus the base names of assignment targets attributed to the
    function scope. Loop variables, ``with``/``as`` and ``except``/``as``
    names, comprehension variables, and nested definition names are not
    recorded in NCM and therefore stay outside this set (conservative:
    preserved verbatim, never force-matched).
    """
    names: set[str] = set()
    for fun in module.functions:
        if fun.id == fun_id:
            names.update(parameter.name for parameter in fun.parameters)
    for assignment in module.assignments:
        if assignment.function_id != fun_id:
            continue
        for target in assignment.target_names:
            base = target.split(".")[0].strip()
            if base:
                names.add(base)
    return frozenset(names)


def _tokenize_bodies(
    modules: dict[str, NormalizedModule],
    texts: dict[str, tuple[str, ...]],
    minimum_tokens: int,
) -> tuple[list[tuple[str, str, int, int, tuple[str, ...]]], list[str], int, int]:
    """Tokenize function bodies; returns (bodies, skip_reasons, skipped, oversized)."""
    bodies: list[tuple[str, str, int, int, tuple[str, ...]]] = []
    reasons: list[str] = []
    skipped = 0
    oversized = 0
    ordered: list[tuple[str, str]] = []
    for path in sorted(modules):
        module = modules[path]
        for fun in sorted(
            module.functions, key=lambda item: (item.location.start_line, item.qualified_name)
        ):
            ordered.append((path, fun.id))
    if len(ordered) > duplicate_analysis.MAX_DUPLICATE_BODIES:
        dropped = ordered[duplicate_analysis.MAX_DUPLICATE_BODIES :]
        ordered = ordered[: duplicate_analysis.MAX_DUPLICATE_BODIES]
        skipped += len(dropped)
        reasons.append(
            f"{len(dropped)} function bodies beyond the duplicate-analysis budget "
            f"({duplicate_analysis.MAX_DUPLICATE_BODIES}) were not compared; not treated as clean"
        )
    by_id = {
        (path, fun.id): (path, fun) for path, module in modules.items() for fun in module.functions
    }
    for path, fun_id in ordered:
        _path, fun = by_id[(path, fun_id)]
        lines = texts.get(path)
        if lines is None:
            skipped += 1
            reasons.append(f"{path}:{fun.qualified_name}: source unavailable for tokenization")
            continue
        text = body_text(list(lines), fun.body_location.start_line, fun.body_location.end_line)
        tokens = normalize_body_tokens(text, local_names=_local_names(modules[path], fun.id))
        if tokens is None:
            skipped += 1
            reasons.append(f"{path}:{fun.qualified_name}: body could not be tokenized")
            continue
        if len(tokens) > duplicate_analysis.MAX_BODY_TOKENS:
            oversized += 1
            skipped += 1
            reasons.append(
                f"{path}:{fun.qualified_name}: body exceeds the tokenization budget "
                f"({duplicate_analysis.MAX_BODY_TOKENS} tokens); not compared"
            )
            continue
        if len(tokens) < minimum_tokens or is_trivial_sequence(tokens):
            continue
        bodies.append(
            (
                path,
                fun.qualified_name,
                fun.body_location.start_line,
                fun.body_location.end_line,
                tokens,
            )
        )
    return bodies, reasons, skipped, oversized


def _build_duplicates(
    modules: dict[str, NormalizedModule],
    texts: dict[str, tuple[str, ...]],
    minimum_tokens: int,
) -> tuple[list[DuplicateGroup], CodeReport]:
    """Run duplicate grouping with explicit coverage accounting."""
    bodies, skip_reasons, skipped, _oversized = _tokenize_bodies(modules, texts, minimum_tokens)
    groups, stats = duplicate_analysis.group_candidates(bodies, minimum_tokens)
    reasons = list(skip_reasons)
    limited = bool(skip_reasons)
    if stats.get("capped"):
        limited = True
        reasons.append(
            "exact matched lengths were capped by the comparison budget; "
            "affected members report a lower bound"
        )
    if stats.get("groups_capped"):
        limited = True
        reasons.append(
            f"candidate groups beyond {duplicate_analysis.MAX_DUPLICATE_GROUPS} "
            "were not reported; not treated as clean"
        )
    report = CodeReport(
        groups=groups,
        compared_bodies=len(bodies),
        skipped_bodies=skipped,
        pair_evaluations_capped=bool(stats.get("capped")),
        limited=limited,
        limitation_reasons=tuple(reasons),
    )
    return groups, report


# --- Rule executors ---------------------------------------------------------


def execute_high_complexity(
    execution_context: RuleExecutionContext, prepared: PreparedCode
) -> RuleOutcome:
    """CODE-HIGH-COMPLEXITY: McCabe strictly above threshold (TASK-140)."""
    context = execution_context.context
    threshold = context.thresholds.complexity
    findings: list[Finding] = []
    measured_any = False
    for (path, _fun_id), values in sorted(prepared.measurements.items()):
        metric = values["complexity"]
        if metric.value is None:
            continue
        measured_any = True
        if metric.value <= threshold:
            continue
        fun = _function_by_id(prepared, path, _fun_id)
        line = fun.location.start_line if fun is not None else 1
        decisions = _decisions_for(prepared, path, _fun_id)
        sites = ", ".join(f"{point.path}:{point.line}" for point in decisions)
        evidence = _function_evidence(path, line, prepared.source_texts)
        rule_limitations: list[Limitation] = []
        note = _partial_note(prepared, path)
        if note is not None:
            rule_limitations.append(note)
        if evidence is None:
            rule_limitations.append(
                Limitation(
                    scope=f"code_structure:{HIGH_COMPLEXITY_SPEC.rule_id}",
                    reason="Source excerpt was unavailable.",
                    path=path,
                    rule_id=HIGH_COMPLEXITY_SPEC.rule_id,
                )
            )
        findings.append(
            create_finding(
                rule_id=HIGH_COMPLEXITY_SPEC.rule_id,
                analyzer_id="code_structure",
                category="code_structure",
                title=f"High complexity: {metric.qualified_name}",
                description=(
                    f"Function {metric.qualified_name} in {path} has McCabe complexity "
                    f"{metric.value} (threshold: complexity > {threshold}, strict). "
                    f"Counted decision points ({len(decisions)}): {sites or 'none listed'}. "
                    f"Basis: {metric.basis} High complexity deserves review for "
                    "maintenance and testing; it is not a claim of bugs or incorrectness."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                location=_function_location(path, line),
                evidence=evidence,
                recommendation=HIGH_COMPLEXITY_SPEC.recommendation,
                limitations=tuple(rule_limitations),
                analyzer_version=context.analyzer_version,
                rule_set_version=context.rule_set_version,
                applied_thresholds=(("complexity", threshold),),
                severity_factors=(f"value {metric.value} against threshold {threshold}",),
                confidence_factors=("pure static measurement; exceedance is certain",),
                analysis_id=context.analysis_id,
                subject_key=f"complexity:{path}:{metric.qualified_name}",
            )
        )
    extra = (
        [
            Limitation(
                scope=f"code_structure:{HIGH_COMPLEXITY_SPEC.rule_id}",
                reason=COMPLEXITY_COVERAGE_NOTE,
            )
        ]
        if measured_any
        else []
    )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(HIGH_COMPLEXITY_SPEC.rule_id, prepared, extra),
    )


def _function_by_id(prepared: PreparedCode, path: str, fun_id: str):  # type: ignore[no-untyped-def]
    module = prepared.modules.get(path)
    if module is None:
        return None
    for fun in module.functions:
        if fun.id == fun_id:
            return fun
    return None


def _decisions_for(prepared: PreparedCode, path: str, fun_id: str):  # type: ignore[no-untyped-def]
    from app.analyzers.code_structure.measurements import DECISION_KINDS

    module = prepared.modules.get(path)
    if module is None:
        return ()
    points = []
    for node in module.control_flow:
        if node.function_id != fun_id or node.kind not in DECISION_KINDS or node.location is None:
            continue
        points.append((node.location.start_line, node.location.start_column, node.kind))
    points.sort()
    from app.analyzers.code_structure.models import DecisionPoint

    return tuple(
        DecisionPoint(kind=kind, path=path, line=line, column=column)
        for line, column, kind in points
    )


def execute_deep_nesting(
    execution_context: RuleExecutionContext, prepared: PreparedCode
) -> RuleOutcome:
    """CODE-DEEP-NESTING: nesting depth strictly above threshold (TASK-141)."""
    context = execution_context.context
    threshold = context.thresholds.nesting
    findings: list[Finding] = []
    for (path, _fun_id), values in sorted(prepared.measurements.items()):
        metric = values["nesting_depth"]
        if metric.value is None:
            continue
        if metric.value <= threshold:
            continue
        fun = _function_by_id(prepared, path, _fun_id)
        line = fun.location.start_line if fun is not None else 1
        deepest = _deepest_for(prepared, path, _fun_id)
        evidence = _function_evidence(path, line, prepared.source_texts)
        rule_limitations: list[Limitation] = []
        note = _partial_note(prepared, path)
        if note is not None:
            rule_limitations.append(note)
        if evidence is None:
            rule_limitations.append(
                Limitation(
                    scope=f"code_structure:{DEEP_NESTING_SPEC.rule_id}",
                    reason="Source excerpt was unavailable.",
                    path=path,
                    rule_id=DEEP_NESTING_SPEC.rule_id,
                )
            )
        findings.append(
            create_finding(
                rule_id=DEEP_NESTING_SPEC.rule_id,
                analyzer_id="code_structure",
                category="code_structure",
                title=f"Deep nesting: {metric.qualified_name}",
                description=(
                    f"Function {metric.qualified_name} in {path} reaches nesting depth "
                    f"{metric.value} (threshold: nesting > {threshold}, strict). "
                    f"Deepest construct at {deepest}. Basis: {metric.basis} Long "
                    "functions are not reported unless actually nested."
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                location=_function_location(path, line),
                evidence=evidence,
                recommendation=DEEP_NESTING_SPEC.recommendation,
                limitations=tuple(rule_limitations),
                analyzer_version=context.analyzer_version,
                rule_set_version=context.rule_set_version,
                applied_thresholds=(("nesting", threshold),),
                severity_factors=(f"value {metric.value} against threshold {threshold}",),
                confidence_factors=("direct structural measurement",),
                analysis_id=context.analysis_id,
                subject_key=f"nesting:{path}:{metric.qualified_name}",
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(DEEP_NESTING_SPEC.rule_id, prepared),
    )


def _deepest_for(prepared: PreparedCode, path: str, fun_id: str) -> str:
    from app.analyzers.code_structure.measurements import nesting_depth

    module = prepared.modules.get(path)
    fun = _function_by_id(prepared, path, fun_id)
    if module is None or fun is None:
        return f"{path}:1"
    metric = nesting_depth(module, fun)
    return f"{metric.deepest_path}:{metric.deepest_line}"


def execute_high_parameter_count(
    execution_context: RuleExecutionContext, prepared: PreparedCode
) -> RuleOutcome:
    """CODE-HIGH-PARAMETER-COUNT: parameter count strictly above threshold (TASK-142)."""
    context = execution_context.context
    threshold = context.thresholds.parameters
    findings: list[Finding] = []
    for (path, _fun_id), values in sorted(prepared.measurements.items()):
        metric = values["parameter_count"]
        if metric.value is None:
            continue
        if metric.value <= threshold:
            continue
        fun = _function_by_id(prepared, path, _fun_id)
        line = fun.location.start_line if fun is not None else 1
        evidence = _function_evidence(path, line, prepared.source_texts)
        rule_limitations: list[Limitation] = []
        note = _partial_note(prepared, path)
        if note is not None:
            rule_limitations.append(note)
        if evidence is None:
            rule_limitations.append(
                Limitation(
                    scope=f"code_structure:{HIGH_PARAMETER_COUNT_SPEC.rule_id}",
                    reason="Source excerpt was unavailable.",
                    path=path,
                    rule_id=HIGH_PARAMETER_COUNT_SPEC.rule_id,
                )
            )
        findings.append(
            create_finding(
                rule_id=HIGH_PARAMETER_COUNT_SPEC.rule_id,
                analyzer_id=CODE_ANALYZER_ID,
                category="code_structure",
                title=f"High parameter count: {metric.qualified_name}",
                description=(
                    f"Function {metric.qualified_name} in {path} declares "
                    f"{metric.value} parameters (threshold: parameters > {threshold}, "
                    f"strict). Basis: {metric.basis} Many parameters are a "
                    "maintenance signal, not proof of a design mistake, and no "
                    "single refactor is prescribed."
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                location=_function_location(path, line),
                evidence=evidence,
                recommendation=HIGH_PARAMETER_COUNT_SPEC.recommendation,
                limitations=tuple(rule_limitations),
                analyzer_version=context.analyzer_version,
                rule_set_version=context.rule_set_version,
                applied_thresholds=(("parameters", threshold),),
                severity_factors=(f"value {metric.value} against threshold {threshold}",),
                confidence_factors=("direct signature measurement",),
                analysis_id=context.analysis_id,
                subject_key=f"parameters:{path}:{metric.qualified_name}",
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(HIGH_PARAMETER_COUNT_SPEC.rule_id, prepared),
    )


def execute_duplicate_candidate(
    execution_context: RuleExecutionContext, prepared: PreparedCode
) -> RuleOutcome:
    """CODE-DUPLICATE-CANDIDATE: grouped bodies sharing a long run (TASK-143)."""
    context = execution_context.context
    threshold = context.thresholds.duplicate_tokens
    extra: list[Limitation] = [
        Limitation(scope=f"code_structure:{DUPLICATE_CANDIDATE_SPEC.rule_id}", reason=reason)
        for reason in prepared.duplicate_report.limitation_reasons
    ]
    if (
        prepared.duplicate_report.compared_bodies > 0
        or prepared.duplicate_report.skipped_bodies > 0
    ):
        extra.append(
            Limitation(
                scope=f"code_structure:{DUPLICATE_CANDIDATE_SPEC.rule_id}",
                reason=(
                    "identifier normalization covers only names positively identified as "
                    "local (parameters and assignment targets recorded in NCM); loop "
                    "variables, with/as and except/as names, comprehension variables, "
                    "and nested definition names are preserved literally and may hide "
                    "rename-matches"
                ),
                rule_id=DUPLICATE_CANDIDATE_SPEC.rule_id,
            )
        )
    findings: list[Finding] = []
    for group in prepared.duplicate_groups:
        primary = group.members[0]
        member_lines = []
        for position, member in enumerate(group.members):
            marker = "primary" if position == 0 else "candidate"
            length = (
                str(member.matched_tokens)
                if member.matched_tokens is not None
                else f">= {threshold}"
            )
            member_lines.append(
                f"- [{marker}] {member.path}:{member.start_line}-{member.end_line} "
                f"{member.qualified_name} ({length} tokens)"
            )
        length_text = (
            str(group.matched_tokens)
            if group.exact
            else f">= {group.matched_tokens} (lower bound; comparison budget capped)"
        )
        evidence = _function_evidence(primary.path, primary.start_line, prepared.source_texts)
        rule_limitations: list[Limitation] = []
        if not group.exact:
            rule_limitations.append(
                Limitation(
                    scope=f"code_structure:{DUPLICATE_CANDIDATE_SPEC.rule_id}",
                    reason="Exact shared lengths were capped by the comparison budget; "
                    "affected members report a lower bound.",
                    rule_id=DUPLICATE_CANDIDATE_SPEC.rule_id,
                )
            )
        if evidence is None:
            rule_limitations.append(
                Limitation(
                    scope=f"code_structure:{DUPLICATE_CANDIDATE_SPEC.rule_id}",
                    reason="Source excerpt was unavailable.",
                    path=primary.path,
                    rule_id=DUPLICATE_CANDIDATE_SPEC.rule_id,
                )
            )
        paths_symbols = ",".join(
            sorted(f"{item.path}#{item.qualified_name}" for item in group.members)
        )
        findings.append(
            create_finding(
                rule_id=DUPLICATE_CANDIDATE_SPEC.rule_id,
                analyzer_id=CODE_ANALYZER_ID,
                category="code_structure",
                title=(
                    f"Duplicate candidate: {primary.qualified_name} "
                    f"and {len(group.members) - 1} other(s)"
                ),
                description=(
                    f"Candidate duplicate code: {len(group.members)} function/method bodies "
                    f"share an identical normalized token run of {length_text} tokens "
                    f"(minimum: duplicate_tokens >= {threshold}). Involved locations:\n"
                    + "\n".join(member_lines)
                    + "\nNormalization: comments/blank lines stripped, whitespace "
                    "normalized, local identifiers mapped to positional placeholders "
                    "(keywords, attribute names, literals preserved). Structural "
                    "similarity may be coincidental or intentional and requires "
                    "manual review; it is not evidence of shared semantics."
                ),
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM
                if group.exact and not prepared.duplicate_report.limited
                else Confidence.LOW,
                location=_function_location(primary.path, primary.start_line),
                evidence=evidence,
                recommendation=DUPLICATE_CANDIDATE_SPEC.recommendation,
                limitations=tuple(rule_limitations),
                analyzer_version=context.analyzer_version,
                rule_set_version=context.rule_set_version,
                applied_thresholds=(("duplicate_tokens", threshold),),
                severity_factors=(f"{len(group.members)} locations sharing a run",),
                confidence_factors=(
                    ("normalized token run shared across locations",)
                    if group.exact
                    else ("comparison budget capped; lengths are lower bounds",)
                ),
                analysis_id=context.analysis_id,
                subject_key=f"duplicate:{paths_symbols}",
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(DUPLICATE_CANDIDATE_SPEC.rule_id, prepared, extra),
    )


# --- Analyzer -----------------------------------------------------------------


def _bind(spec: CodeRuleSpec, analyzer: CodeStructureAnalyzer, kind: str) -> RegisteredRule:
    """Bind a rule implementation to metadata plus analyzer-owned inputs."""

    def execute(execution_context: RuleExecutionContext) -> RuleOutcome:
        prepared = analyzer.prepared_for(execution_context.context)
        if kind == "complexity":
            return execute_high_complexity(execution_context, prepared)
        if kind == "nesting":
            return execute_deep_nesting(execution_context, prepared)
        if kind == "parameters":
            return execute_high_parameter_count(execution_context, prepared)
        return execute_duplicate_candidate(execution_context, prepared)

    metadata = RuleMetadata(
        rule_id=spec.rule_id,
        name=spec.name,
        description=spec.description,
        analyzer_id=CODE_ANALYZER_ID,
        version=CODE_ANALYZER_VERSION,
        default_severity=spec.default_severity,
        documentation_ref=spec.documentation_ref,
    )
    return RegisteredRule(metadata=metadata, execute=execute)


def build_code_structure_rules(analyzer: CodeStructureAnalyzer) -> list[RegisteredRule]:
    """Build the registered code-structure rules (deterministic rule-ID order)."""
    bound = [
        _bind(HIGH_COMPLEXITY_SPEC, analyzer, "complexity"),
        _bind(DEEP_NESTING_SPEC, analyzer, "nesting"),
        _bind(HIGH_PARAMETER_COUNT_SPEC, analyzer, "parameters"),
        _bind(DUPLICATE_CANDIDATE_SPEC, analyzer, "duplicates"),
    ]
    return sorted(bound, key=lambda rule: rule.metadata.rule_id)


class CodeStructureAnalyzer(Analyzer):
    """Static code-structure analyzer over NCM plus bounded source excerpts."""

    id = CODE_ANALYZER_ID
    name = "Code Structure Analyzer"
    version = CODE_ANALYZER_VERSION

    def __init__(self, source: SourceProvider | None = None) -> None:
        self._source = source
        self._prepared_cache: dict[str, PreparedCode] = {}

    def prepared_for(self, context: object) -> PreparedCode:
        """Measurements, token groups, and source lines (cached per analysis ID)."""
        analysis_id = getattr(context, "analysis_id", "-")
        cached = self._prepared_cache.get(analysis_id)
        if cached is not None:
            return cached
        ncm = getattr(context, "ncm", None)
        if ncm is None:
            from app.ncm import NcmRepository as _NcmRepository

            ncm = _NcmRepository(analysis_id=analysis_id)
        thresholds = getattr(context, "thresholds", None)
        if thresholds is None:
            from app.analyzers.thresholds import default_thresholds

            thresholds = default_thresholds()
        modules, failed, unsupported, partial, reasons = _scan_ncm(ncm)
        texts = _read_sources(self._source, sorted(modules))
        measurements = _measure_all(modules)
        groups: list[DuplicateGroup] = []
        duplicate_report = CodeReport()
        if self._source is not None:
            minimum = thresholds.duplicate_tokens
            groups, duplicate_report = _build_duplicates(modules, texts, minimum)
            reasons = list(reasons)
            for reason in duplicate_report.limitation_reasons:
                reasons.append(reason)
        else:
            reasons = list(reasons)
            reasons.append(
                "duplicate analysis requires bounded source lines; the "
                "CODE-DUPLICATE-CANDIDATE rule was not evaluated and this is "
                "not a clean result"
            )
        prepared = PreparedCode(
            modules=modules,
            source_texts=texts,
            measurements=measurements,
            duplicate_report=duplicate_report,
            duplicate_groups=groups,
            failed_files=failed,
            unsupported_files=unsupported,
            partial_modules=partial,
            python_paths=tuple(sorted(modules)),
            limitation_reasons=tuple(reasons),
        )
        self._prepared_cache[analysis_id] = prepared
        log_event(
            _logger,
            logging.INFO,
            "code_structure.prepared",
            "Code-structure analysis inputs prepared",
            analysis_id=analysis_id,
            functions=len(measurements),
            duplicate_groups=len(groups),
        )
        return prepared

    def rules(self) -> list[RegisteredRule]:
        """Only the registered V1.0 code-structure rules (never other domains)."""
        return build_code_structure_rules(self)

    def measurements_for(
        self, context: AnalysisContext
    ) -> dict[tuple[str, str], dict[str, FunctionMeasurement]]:
        """Per-function measurements for serialization and hotspot building."""
        return self.prepared_for(context).measurements

    def duplicates_for(self, context: AnalysisContext) -> tuple[list[DuplicateGroup], CodeReport]:
        """Duplicate groups plus coverage report for serialization."""
        prepared = self.prepared_for(context)
        return prepared.duplicate_groups, prepared.duplicate_report

    def hotspots(self, context: AnalysisContext) -> list[Hotspot]:
        """Review-ordered hotspots built from findings plus measurements."""
        prepared = self.prepared_for(context)
        result = self.analyze(context)
        thresholds = getattr(context, "thresholds", None)
        if thresholds is None:
            from app.analyzers.thresholds import default_thresholds

            thresholds = default_thresholds()
        by_location: dict[tuple[str, int, int], list[tuple[str, str, int | None]]] = {}
        for (path, _fun_id), values in prepared.measurements.items():
            fun = _function_by_id(prepared, path, _fun_id)
            if fun is None:
                continue
            line = fun.location.start_line
            column = fun.location.start_column
            fired: list[tuple[str, str, int | None]] = []
            complexity = values["complexity"]
            if complexity.value is not None and complexity.value > thresholds.complexity:
                fired.append(("CODE-HIGH-COMPLEXITY", "complexity", complexity.value))
            nesting = values["nesting_depth"]
            if nesting.value is not None and nesting.value > thresholds.nesting:
                fired.append(("CODE-DEEP-NESTING", "nesting_depth", nesting.value))
            params = values["parameter_count"]
            if params.value is not None and params.value > thresholds.parameters:
                fired.append(("CODE-HIGH-PARAMETER-COUNT", "parameter_count", params.value))
            if fired:
                by_location.setdefault((path, line, column), []).extend(fired)
        findings_by_key: dict[tuple[str, int, int], dict[str, Finding]] = {}
        for finding in result.findings:
            location = finding.location
            findings_by_key.setdefault(
                (location.file_path, location.start_line, location.start_column), {}
            )[finding.rule_id] = finding
        inputs: list[HotspotInput] = []
        for key in sorted(by_location):
            fun = _function_at(prepared, key)
            if fun is None:
                continue
            kind = fun.kind if fun.kind in ("function", "method") else "function"
            for rule_id, metric, value in sorted(by_location[key]):
                matched = findings_by_key.get(key, {}).get(rule_id)
                if matched is None:
                    continue
                applied = dict(matched.applied_thresholds)
                inputs.append(
                    HotspotInput(
                        finding=matched,
                        path=key[0],
                        symbol=fun.qualified_name,
                        kind=kind,
                        metric=metric,
                        value=value,
                        thresholds={name: applied.get(name) for name in sorted(applied)},
                    )
                )
        return build_hotspots(inputs)

    def coverage(self, ncm: NcmRepository) -> list[Coverage]:
        """Explicit per-rule coverage for an NCM snapshot (never clean)."""
        python_paths = [
            entry.path
            for entry in ncm.files
            if entry.module is not None and (entry.language or "").lower() == "python"
        ]
        report_limited = any(
            entry.parse_state == "failed"
            or (entry.module is not None and entry.module.completeness != "fully")
            for entry in ncm.files
        )
        rows: list[Coverage] = []
        for spec in CODE_RULE_SPECS:
            if not python_paths:
                rows.append(
                    Coverage(
                        rule_id=spec.rule_id,
                        status=CoverageStatus.UNSUPPORTED,
                        reason="No supported-language (python) content in scope.",
                    )
                )
            elif spec.rule_id == "CODE-DUPLICATE-CANDIDATE" and self._source is None:
                rows.append(
                    Coverage(
                        rule_id=spec.rule_id,
                        status=CoverageStatus.NOT_APPLICABLE,
                        reason="Duplicate analysis requires bounded source lines; "
                        "the rule was not evaluated.",
                    )
                )
            elif report_limited:
                rows.append(
                    Coverage(
                        rule_id=spec.rule_id,
                        status=CoverageStatus.PARTIALLY_COVERED,
                        reason="Extraction incomplete (failed or partial files); "
                        "measurements may be understated.",
                    )
                )
            else:
                rows.append(
                    Coverage(
                        rule_id=spec.rule_id,
                        status=CoverageStatus.COVERED,
                        reason="Applicable functions analyzed with a sufficient representation.",
                    )
                )
        log_event(
            _logger,
            logging.INFO,
            "code_structure.coverage.computed",
            "Code-structure coverage computed",
            coverage={item.rule_id: item.status.value for item in rows},
        )
        return rows


def _function_at(prepared: PreparedCode, key: tuple[str, int, int]):  # type: ignore[no-untyped-def]
    path, line, column = key
    module = prepared.modules.get(path)
    if module is None:
        return None
    for fun in module.functions:
        if fun.location.start_line == line and fun.location.start_column == column:
            return fun
    return None


__all__ = [
    "CODE_ANALYZER_ID",
    "CodeStructureAnalyzer",
    "build_code_structure_rules",
]
