"""SEC-PATH-TRAVERSAL: potential path traversal (TASK-099).

Flags filesystem operations whose path argument is built from externally
influenced or unresolved input without visible evidence of
canonicalization or containment validation in the local scope. Fixed
paths are not reported; visibly validated paths are not reported. A
dynamic path alone never yields high confidence.
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
from app.analyzers.security.metadata import PATH_TRAVERSAL_SPEC
from app.analyzers.security.sinks import PATH_SINKS, callee_matches
from app.analyzers.security.source import SourceProvider, mask_strings

SPEC = PATH_TRAVERSAL_SPEC

_RESOLVE_RE = re.compile(r"\.\s*resolve\s*\(")
_CONTAINMENT_RE = re.compile(r"relative_to|commonpath|startswith|\bin\b.*base|base.*\bin\b")
_TRAVERSAL_MARKER_RE = re.compile(r"\.\.")


def _matcher(callee: str, import_targets: frozenset[str]) -> bool:
    return callee_matches(callee, PATH_SINKS, import_targets)


def _path_constructor_only(callee: str) -> bool:
    base = callee.rpartition(".")[2]
    return base == "Path" or callee in ("pathlib.Path", "Path")


def _has_visible_validation(scope_text: str) -> bool:
    masked = mask_strings(scope_text)
    return bool(_RESOLVE_RE.search(masked) and _CONTAINMENT_RE.search(masked))


def _combined_info(sink: SinkCall):
    combined = sink.first_arg
    if sink.keyword_text.strip():
        combined += "\n" + sink.keyword_text
    return analyze_expression(combined)


def evaluate_sink(sink: SinkCall) -> EvaluatedSink | None:
    """Evaluate one candidate filesystem sink (None = no finding)."""
    if not sink.first_arg.strip():
        return None
    info = _combined_info(sink)
    if not info.is_dynamic:
        return None
    if _has_visible_validation(sink.scope_text):
        return None
    origins = [sink.assignments.origin_of(name, sink.call.function_id) for name in info.identifiers]
    worst = worst_origin(origins) if origins else Origin.UNRESOLVED
    if worst is Origin.CONSTANT:
        return None
    if worst is Origin.EXTERNAL:
        severity, confidence = Severity.HIGH, Confidence.HIGH
    elif worst is Origin.UNRESOLVED:
        severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
    else:
        severity, confidence = Severity.LOW, Confidence.LOW
    confidence = adjust_for_partial(confidence, sink.partial)
    basis = evidence_basis(info.identifiers, sink)
    names = ", ".join(info.identifiers[:3]) if info.identifiers else "dynamic expression"
    traversal_note = (
        " The path text contains traversal-sensitive markers (`..`), which "
        "strengthens the need for review."
        if _TRAVERSAL_MARKER_RE.search(mask_strings(sink.first_arg))
        else ""
    )
    constructor_note = (
        " Path construction alone does not access the filesystem, but the "
        "constructed value typically flows into filesystem operations."
        if _path_constructor_only(sink.call.callee_text)
        else ""
    )
    description = (
        f"Potential path traversal: user-controlled or unresolved input "
        f"({names}) reaches the filesystem sink `{sink.call.callee_text}` "
        "without visible evidence of canonicalization or containment "
        f"validation in the local scope.{traversal_note}{constructor_note} "
        f"Evidence basis: {basis}. This pattern deserves security review; it "
        "is not a confirmed vulnerability."
    )
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="Potential path traversal in dynamically built path",
        description=description,
        subject_key=subject_key(sink.call.callee_text, info.identifiers),
        severity_factors=(f"origin: {worst.value}", "no visible path validation"),
        confidence_factors=(f"origin category: {worst.value}", f"evidence basis: {basis}"),
        impact=(
            "If untrusted input can control the path, an attacker could read, "
            "overwrite, or delete files outside the intended directory."
        ),
    )


def execute_path_traversal(
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
