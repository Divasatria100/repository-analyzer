"""Shared injection-rule harness (TASK-094/096 support).

Every injection rule follows the same evidence-based shape:

1. Walk Python modules in NCM (deterministic path order).
2. Keep call sites whose NCM ``callee_text`` matches the rule's sinks.
3. Extract the bounded call text around the NCM location (read as data).
4. Classify the sink argument (dynamic vs constant) and resolve value
   origins through the bounded local assignment map.
5. Emit findings through the common Finding model, sorted and deduplicated.

Rule files supply only sink matching and per-sink evaluation. Nothing
here executes repository code, imports it, or contacts a network.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from app.analyzers.findings import Confidence, Finding, Limitation, Severity, create_finding
from app.analyzers.rules import RuleExecutionContext, RuleOutcome
from app.analyzers.security.coverage import (
    Coverage,
    CoverageStatus,
    ScopeSummary,
    coverage_for,
    summarize_scope,
)
from app.analyzers.security.evidence import build_security_evidence
from app.analyzers.security.flow import (
    AssignmentMap,
    ExpressionInfo,
    analyze_expression,
    build_assignment_map,
)
from app.analyzers.security.metadata import SecurityRuleSpec
from app.analyzers.security.source import (
    SourceFile,
    SourceProvider,
    balanced_span,
    structure_mask,
)
from app.ncm import CallSite, FunctionDef, NormalizedModule

#: Identifier for findings whose flow could not be fully resolved.
UNRESOLVED_NOTE = "The value origin could not be fully resolved; treated as unresolved."


@dataclass
class SinkCall:
    """One candidate sink call with its bounded static context."""

    module: NormalizedModule
    call: CallSite
    call_text: str
    first_arg: str
    first_info: ExpressionInfo
    has_extra_args: bool
    keyword_text: str
    assignments: AssignmentMap
    scope_text: str
    import_targets: frozenset[str]
    function: FunctionDef | None
    source: SourceFile | None
    partial: bool


@dataclass
class EvaluatedSink:
    """A rule's verdict for one sink call (finding or explicit silence)."""

    severity: Severity
    confidence: Confidence
    title: str
    description: str
    subject_key: str
    severity_factors: tuple[str, ...] = ()
    confidence_factors: tuple[str, ...] = ()
    limitations: tuple[Limitation, ...] = ()
    impact: str | None = None


def module_functions(module: NormalizedModule) -> dict[str, FunctionDef]:
    """Index functions by ID for scope/parameter lookup."""
    return {function.id: function for function in module.functions}


def function_parameters(module: NormalizedModule) -> dict[str, frozenset[str]]:
    """Map function ID to declared non-self parameter names."""
    params: dict[str, frozenset[str]] = {}
    for function in module.functions:
        names = frozenset(param.name for param in function.parameters if not param.is_self_cls)
        params[function.id] = names
    return params


def split_call_args(call_text: str) -> tuple[str, list[str]]:
    """Split a balanced call span into first arg plus remaining segments.

    Segmentation runs on the length-preserving structural mask while
    slices are taken from the original text, so offsets stay aligned.
    """
    masked = structure_mask(call_text)
    open_index = masked.find("(")
    if open_index == -1:
        return "", []
    depth = 0
    bracket_depth = 0
    segment_start = open_index + 1
    segments: list[str] = []
    for position in range(open_index, len(masked)):
        char = masked[position]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                segments.append(call_text[segment_start:position])
                break
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "," and depth == 1 and bracket_depth == 0:
            segments.append(call_text[segment_start:position])
            segment_start = position + 1
    if not segments:
        return "", []
    return segments[0].strip(), [segment.strip() for segment in segments[1:]]


def collect_sink_calls(
    module: NormalizedModule,
    source: SourceFile | None,
    matcher: Callable[[str, frozenset[str]], bool],
) -> tuple[list[SinkCall], frozenset[str]]:
    """Gather candidate sink calls in deterministic location order."""
    import_targets = frozenset(imp.target_text for imp in module.imports)
    functions = module_functions(module)
    parameters = function_parameters(module)
    calls = sorted(module.calls, key=lambda c: (c.location.start_line, c.location.start_column))
    lines = list(source.lines) if source is not None else []
    found: list[SinkCall] = []
    for call in calls:
        if not matcher(call.callee_text, import_targets):
            continue
        if source is None:
            call_text = ""
        else:
            call_text = balanced_span(lines, call.location.start_line, call.location.start_column)
        first_arg, rest = split_call_args(call_text) if call_text else ("", [])
        function = functions.get(call.function_id or "")
        if function is not None:
            scope_start: int | None = function.body_location.start_line
        else:
            scope_start = None
        assignments = (
            build_assignment_map(lines, call.location.start_line, scope_start, parameters)
            if source is not None
            else AssignmentMap(facts={}, parameters={})
        )
        scope_text = _scope_text(lines, call.location.start_line, scope_start)
        found.append(
            SinkCall(
                module=module,
                call=call,
                call_text=call_text,
                first_arg=first_arg,
                first_info=analyze_expression(first_arg) if first_arg else analyze_expression(""),
                has_extra_args=bool(rest),
                keyword_text="\n".join(rest),
                assignments=assignments,
                scope_text=scope_text,
                import_targets=import_targets,
                function=function,
                source=source,
                partial=module.completeness != "fully",
            )
        )
    return found, import_targets


def _scope_text(lines: list[str], focus_line: int, scope_start: int | None) -> str:
    if not lines:
        return ""
    if scope_start is not None:
        start = max(0, scope_start - 1)
    else:
        start = max(0, focus_line - 41)
    end = min(len(lines), focus_line + 10)
    return "\n".join(lines[start:end])


def make_finding(
    *,
    spec: SecurityRuleSpec,
    analyzer_version: str,
    rule_set_version: str,
    analysis_id: str,
    sink: SinkCall,
    verdict: EvaluatedSink,
) -> Finding:
    """Build one validated finding with deterministic identity + evidence."""
    location = sink.call.location
    evidence = build_security_evidence(
        path=location.file_path,
        focus_start_line=location.start_line,
        focus_end_line=location.end_line,
        lines=sink.source.lines if sink.source is not None else None,
    )
    limitations = list(verdict.limitations)
    if evidence is None:
        limitations.append(
            Limitation(
                scope=f"security:{spec.rule_id}",
                reason="Source excerpt was unavailable; the finding rests on the "
                "NCM sink location and the described pattern.",
                path=location.file_path,
                rule_id=spec.rule_id,
            )
        )
    if sink.partial:
        limitations.append(
            Limitation(
                scope=f"security:{spec.rule_id}",
                reason="The containing module is only partially represented; "
                "confidence is reduced accordingly.",
                path=location.file_path,
                rule_id=spec.rule_id,
            )
        )
    return create_finding(
        rule_id=spec.rule_id,
        analyzer_id="security",
        category="security",
        title=verdict.title,
        description=verdict.description,
        severity=verdict.severity,
        confidence=verdict.confidence,
        location=location,
        evidence=evidence,
        recommendation=spec.recommendation,
        limitations=tuple(limitations),
        analyzer_version=analyzer_version,
        rule_set_version=rule_set_version,
        impact=verdict.impact,
        severity_factors=verdict.severity_factors,
        confidence_factors=verdict.confidence_factors,
        analysis_id=analysis_id,
        subject_key=verdict.subject_key,
    )


def base_limitations(rule_id: str, scope_summary: ScopeSummary) -> list[Limitation]:
    """Explicit limitations for failed/partial/unsupported files (never clean)."""
    limitations: list[Limitation] = []
    for path in scope_summary.failed_python_files:
        limitations.append(
            Limitation(
                scope=f"security:{rule_id}",
                reason="A Python file failed to parse; security analysis is "
                "incomplete for it and it is not treated as clean.",
                path=path,
                rule_id=rule_id,
            )
        )
    for path in scope_summary.partial_modules:
        limitations.append(
            Limitation(
                scope=f"security:{rule_id}",
                reason="A Python module is only partially represented; findings "
                "in it carry reduced confidence.",
                path=path,
                rule_id=rule_id,
            )
        )
    for path in scope_summary.unsupported_files:
        limitations.append(
            Limitation(
                scope=f"security:{rule_id}",
                reason="A file uses an unsupported language; the rule was not "
                "applied to it and it is not treated as clean.",
                path=path,
                rule_id=rule_id,
            )
        )
    return limitations


def subject_key(callee: str, identifiers: tuple[str, ...]) -> str:
    """Stable subject discriminator for finding identity (sorted, bounded)."""
    names = ",".join(sorted(set(identifiers))[:3]) or "dynamic"
    return f"{callee}:{names}"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministic finding order (never traversal order)."""
    return sorted(
        findings,
        key=lambda f: (
            f.location.file_path,
            f.location.start_line,
            f.location.start_column,
            f.rule_id,
            f.identity_key,
        ),
    )


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Drop duplicate identities, keeping the first in sorted order."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in sort_findings(findings):
        if finding.identity_key in seen:
            continue
        seen.add(finding.identity_key)
        unique.append(finding)
    return unique


def run_rule_with_sinks(
    *,
    spec: SecurityRuleSpec,
    execution_context: RuleExecutionContext,
    source: SourceProvider | None,
    matcher: Callable[[str, frozenset[str]], bool],
    evaluate: Callable[[SinkCall], EvaluatedSink | None],
) -> tuple[RuleOutcome, Coverage]:
    """Execute one injection rule over NCM sink calls (shared pipeline)."""
    context = execution_context.context
    scope = summarize_scope(context.ncm)
    limitations = base_limitations(spec.rule_id, scope)
    if not scope.has_supported_content:
        coverage = coverage_for(spec.rule_id, scope, sinks_found=False)
        limitations.append(
            Limitation(
                scope=f"security:{spec.rule_id}",
                reason=coverage.reason,
                rule_id=spec.rule_id,
            )
        )
        return RuleOutcome(findings=[], limitations=limitations), coverage
    findings: list[Finding] = []
    sinks_seen = False
    unevaluated = False
    for path in scope.python_modules:
        module = next((m for m in context.ncm.modules if m.file_path == path), None)
        if module is None:
            continue
        source_file = source.read(path) if source is not None else None
        if source_file is None:
            unevaluated = True
            limitations.append(
                Limitation(
                    scope=f"security:{spec.rule_id}",
                    reason="Source lines were unavailable for a Python module; "
                    "its sinks could not be evaluated and it is not clean.",
                    path=path,
                    rule_id=spec.rule_id,
                )
            )
            continue
        sink_calls, _ = collect_sink_calls(module, source_file, matcher)
        sinks_seen = sinks_seen or bool(sink_calls)
        for sink in sink_calls:
            verdict = evaluate(sink)
            if verdict is None:
                continue
            findings.append(
                make_finding(
                    spec=spec,
                    analyzer_version=context.analyzer_version,
                    rule_set_version=context.rule_set_version,
                    analysis_id=context.analysis_id,
                    sink=sink,
                    verdict=verdict,
                )
            )
    coverage = coverage_for(spec.rule_id, scope, sinks_found=sinks_seen)
    if unevaluated and coverage.status is not CoverageStatus.PARTIALLY_COVERED:
        coverage = Coverage(
            rule_id=spec.rule_id,
            status=CoverageStatus.PARTIALLY_COVERED,
            reason=(
                "Some supported modules could not be evaluated because their "
                "source lines were unavailable; they are not treated as clean."
            ),
        )
    if coverage.status.value in ("not_applicable",):
        limitations.append(
            Limitation(
                scope=f"security:{spec.rule_id}",
                reason=coverage.reason,
                rule_id=spec.rule_id,
            )
        )
    return RuleOutcome(findings=dedupe_findings(findings), limitations=limitations), coverage


SHELL_TRUE_RE = re.compile(r"\bshell\s*=\s*True\b")
SHELL_FALSE_RE = re.compile(r"\bshell\s*=\s*False\b")


def adjust_for_partial(confidence: Confidence, partial: bool) -> Confidence:
    """Cap High confidence at Medium for partially represented modules."""
    if partial and confidence is Confidence.HIGH:
        return Confidence.MEDIUM
    return confidence


def evidence_basis(identifiers: tuple[str, ...], sink: SinkCall) -> str:
    """Local relationship when identifiers resolve locally, else pattern."""
    facts = sink.assignments.facts
    params = sink.assignments.parameters.get(sink.call.function_id or "", frozenset())
    if any(name in facts or name in params for name in identifiers):
        return "local relationship"
    return "pattern"
