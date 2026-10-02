"""SEC-SQL-INJECTION: potential SQL injection (TASK-097).

Flags dynamically constructed SQL statement text reaching a recognized
query execution API (``execute``/``executemany``/``executescript`` with
database-import or database-handle corroboration). Static statements and
parameterized queries with static text are not reported. Wording is
investigation-oriented: potential issue, not a confirmed vulnerability.
"""

from __future__ import annotations

import re

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
from app.analyzers.security.flow import Origin, analyze_expression, worst_origin
from app.analyzers.security.metadata import SQL_INJECTION_SPEC
from app.analyzers.security.sinks import sql_sink_match
from app.analyzers.security.source import SourceProvider

SPEC = SQL_INJECTION_SPEC

_PARAMS_KWARG_RE = re.compile(r"\bparams?\s*=")


def _mechanism(first_arg: str) -> str:
    info = analyze_expression(first_arg)
    parts: list[str] = []
    if info.has_fstring:
        parts.append("f-string interpolation")
    if info.has_format:
        parts.append("% formatting or str.format")
    if info.has_concat and not info.has_fstring and not info.has_format:
        parts.append("string concatenation")
    if not parts and info.identifiers:
        parts.append("variable propagation")
    return ", ".join(parts) if parts else "dynamic construction"


def _origin_phrase(origin: Origin) -> str:
    if origin is Origin.EXTERNAL:
        return "externally influenced input"
    if origin is Origin.UNRESOLVED:
        return "input whose origin could not be resolved"
    return "configurable input"


def evaluate_sink(sink: SinkCall) -> EvaluatedSink | None:
    """Evaluate one candidate ``execute*`` call (None = no finding)."""
    if not sink.first_arg.strip():
        return None
    info = sink.first_info
    if not info.is_dynamic:
        return None
    origins = [sink.assignments.origin_of(name, sink.call.function_id) for name in info.identifiers]
    worst = worst_origin(origins) if origins else Origin.UNRESOLVED
    if worst is Origin.CONSTANT:
        # Dynamic construction over constant parts only: not reported.
        return None
    parameterized = sink.has_extra_args or bool(_PARAMS_KWARG_RE.search(sink.keyword_text))
    if worst is Origin.EXTERNAL:
        severity, confidence = Severity.HIGH, Confidence.HIGH
    elif worst is Origin.UNRESOLVED:
        severity, confidence = Severity.HIGH, Confidence.MEDIUM
    else:
        severity, confidence = Severity.MEDIUM, Confidence.LOW
    confidence = adjust_for_partial(confidence, sink.partial)
    basis = evidence_basis(info.identifiers, sink)
    names = ", ".join(info.identifiers[:3]) if info.identifiers else "dynamic expression"
    param_note = (
        " Although additional query parameters are passed, the statement text "
        "itself is built dynamically, so review is still warranted."
        if parameterized
        else ""
    )
    description = (
        f"Potential SQL injection: {_origin_phrase(worst)} ({names}) reaches "
        f"the SQL execution sink `{sink.call.callee_text}` through "
        f"{_mechanism(sink.first_arg)}. The statement text is not static and "
        f"no safe parameterization of the dynamic parts is visible.{param_note} "
        f"Evidence basis: {basis}. This pattern deserves security review; it "
        "is not a confirmed vulnerability."
    )
    factors = [f"dynamic SQL text via {_mechanism(sink.first_arg)}", f"origin: {worst.value}"]
    if parameterized:
        factors.append("additional parameters passed but text still dynamic")
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="Potential SQL injection in dynamically built query",
        description=description,
        subject_key=subject_key(sink.call.callee_text, info.identifiers),
        severity_factors=tuple(factors),
        confidence_factors=(f"origin category: {worst.value}", f"evidence basis: {basis}"),
        impact=(
            "If untrusted input reaches the statement, an attacker could read, "
            "alter, or delete data, or bypass authentication logic."
        ),
    )


def execute_sql_injection(
    execution_context: RuleExecutionContext, source: SourceProvider | None
) -> tuple[RuleOutcome, Coverage]:
    """Rule entry point (returns outcome plus explicit coverage)."""
    return run_rule_with_sinks(
        spec=SPEC,
        execution_context=execution_context,
        source=source,
        matcher=sql_sink_match,
        evaluate=evaluate_sink,
    )
