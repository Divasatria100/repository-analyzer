"""SEC-DANGEROUS-DYNAMIC-EXECUTION: potential dangerous dynamic execution (TASK-102).

Flags externally influenced or unresolved content reaching builtin
dynamic-execution calls (``eval``, ``exec``, ``compile``,
``__import__`` with a dynamic name). Static constant expressions are
reported at most at Info severity; ``ast.literal_eval``, SQL execution,
and subprocess command execution belong to other rules and are never
reported here. Detected code is never executed by the analyzer.
"""

from __future__ import annotations

from app.analyzers.findings import Confidence, Severity
from app.analyzers.rules import RuleExecutionContext, RuleOutcome
from app.analyzers.security.common import (
    EvaluatedSink,
    SinkCall,
    adjust_for_partial,
    evidence_basis,
    run_rule_with_sinks,
    subject_key,
)
from app.analyzers.security.coverage import Coverage
from app.analyzers.security.flow import Origin, worst_origin
from app.analyzers.security.metadata import DANGEROUS_DYNAMIC_EXECUTION_SPEC
from app.analyzers.security.sinks import DYNAMIC_EXEC_EXCLUSIONS, DYNAMIC_EXEC_SINKS, callee_matches
from app.analyzers.security.source import SourceProvider

SPEC = DANGEROUS_DYNAMIC_EXECUTION_SPEC


def _matcher(callee: str, import_targets: frozenset[str]) -> bool:
    if callee in DYNAMIC_EXEC_EXCLUSIONS:
        return False
    return callee_matches(callee, DYNAMIC_EXEC_SINKS, import_targets)


def _origin_phrase(origin: Origin) -> str:
    if origin is Origin.EXTERNAL:
        return "externally influenced input"
    if origin is Origin.UNRESOLVED:
        return "input whose origin could not be resolved"
    return "configurable input"


def evaluate_sink(sink: SinkCall) -> EvaluatedSink | None:
    """Evaluate one candidate dynamic-execution call (None = no finding)."""
    if not sink.first_arg.strip():
        return None
    api = sink.call.callee_text
    info = sink.first_info
    if not info.is_dynamic:
        if api in ("compile", "__import__"):
            # Compiling a constant builds no attacker-reachable behavior,
            # and a static module name is an ordinary import.
            return None
        confidence = adjust_for_partial(Confidence.LOW, sink.partial)
        return EvaluatedSink(
            severity=Severity.INFO,
            confidence=confidence,
            title="Static expression passed to dynamic execution",
            description=(
                f"A static, developer-controlled expression reaches `{api}`. "
                "No untrusted input is visible, so this is not a dynamic "
                "injection pattern, but dynamic execution deserves review. "
                "Evidence basis: pattern."
            ),
            subject_key=f"{api}:constant",
            severity_factors=("constant expression", f"dynamic API: {api}"),
            confidence_factors=("origin category: constant", "evidence basis: pattern"),
            impact=(
                "Static use carries little direct risk, but the dynamic "
                "execution API widens impact if its input ever becomes dynamic."
            ),
        )
    origins = [sink.assignments.origin_of(name, sink.call.function_id) for name in info.identifiers]
    worst = worst_origin(origins) if origins else Origin.UNRESOLVED
    if worst is Origin.CONSTANT:
        if api in ("compile", "__import__"):
            return None
        confidence = adjust_for_partial(Confidence.LOW, sink.partial)
        return EvaluatedSink(
            severity=Severity.INFO,
            confidence=confidence,
            title="Static expression passed to dynamic execution",
            description=(
                f"Constant-valued content reaches `{api}`. No untrusted input "
                "is visible. Evidence basis: pattern."
            ),
            subject_key=f"{api}:constant",
            severity_factors=("constant-valued content", f"dynamic API: {api}"),
            confidence_factors=("origin category: constant", "evidence basis: pattern"),
            impact="Static use carries little direct risk unless its input becomes dynamic.",
        )
    if worst is Origin.EXTERNAL:
        severity = Severity.CRITICAL if api in ("eval", "exec") else Severity.HIGH
        confidence = Confidence.HIGH
    elif worst is Origin.UNRESOLVED:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW
    confidence = adjust_for_partial(confidence, sink.partial)
    basis = evidence_basis(info.identifiers, sink)
    names = ", ".join(info.identifiers[:3]) if info.identifiers else "dynamic expression"
    if api == "compile":
        behavior = (
            "constructs an executable code object from the flagged content; "
            "executing it would run attacker-influenced code"
        )
    elif api == "__import__":
        behavior = "loads a module selected by the flagged content"
    else:
        behavior = "is executed with the privileges of the process"
    description = (
        f"Potential dangerous dynamic execution: {_origin_phrase(worst)} "
        f"({names}) reaches `{api}`, which {behavior}. Evidence basis: "
        f"{basis}. This pattern deserves security review; it is not a "
        "confirmed vulnerability, and the content was not executed."
    )
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="Potential dangerous dynamic execution of untrusted content",
        description=description,
        subject_key=subject_key(api, info.identifiers),
        severity_factors=(f"dynamic API: {api}", f"origin: {worst.value}"),
        confidence_factors=(f"origin category: {worst.value}", f"evidence basis: {basis}"),
        impact=(
            "If untrusted content can be executed, an attacker could run "
            "arbitrary code with the privileges of the process."
        ),
    )


def execute_dangerous_dynamic_execution(
    execution_context: RuleExecutionContext, source: SourceProvider | None
) -> tuple[RuleOutcome, Coverage]:
    """Rule entry point (returns outcome plus explicit coverage)."""
    return run_rule_with_sinks(
        spec=SPEC,
        execution_context=execution_context,
        source=source,
        matcher=_matcher,
        evaluate=evaluate_sink,
    )
