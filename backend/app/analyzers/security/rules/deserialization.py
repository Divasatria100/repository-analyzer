"""SEC-UNSAFE-DESERIALIZATION: potential unsafe deserialization (TASK-101).

Flags serialized data of externally influenced, unresolved, or
insufficiently trusted origin reaching a deserialization mechanism
capable of arbitrary object construction (pickle/marshal families,
shelve, unsafe YAML loaders). Data-only formats (JSON, safe/full YAML
loaders) are never reported; fixed local constants are not reported.
Wording is investigation-oriented: potential issue, not a confirmed
vulnerability.
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
from app.analyzers.security.flow import Origin, worst_origin
from app.analyzers.security.metadata import UNSAFE_DESERIALIZATION_SPEC
from app.analyzers.security.sinks import (
    DESERIALIZATION_SINKS,
    SAFE_DESERIALIZATION_CALLEES,
    YAML_SAFE_LOADERS,
    YAML_UNSAFE_LOADERS,
    callee_matches,
)
from app.analyzers.security.source import SourceProvider, mask_strings

SPEC = UNSAFE_DESERIALIZATION_SPEC

_LOADER_KWARG_RE = re.compile(r"\bLoader\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)")


def _matcher(callee: str, import_targets: frozenset[str]) -> bool:
    if callee in SAFE_DESERIALIZATION_CALLEES or callee.rpartition(".")[2] in (
        "safe_load",
        "safe_load_all",
        "full_load",
    ):
        return False
    head = callee.split(".")[0]
    if head in ("json", "ujson", "simplejson", "orjson"):
        # Data-only JSON family: never an unsafe object-deserialization sink.
        return False
    return callee_matches(callee, DESERIALIZATION_SINKS, import_targets)


def _mechanism(callee: str) -> str:
    base = callee.rpartition(".")[2]
    family = callee.rpartition(".")[0] or callee
    if base in ("loads", "load"):
        return f"{family} object deserialization"
    return f"{family} deserialization"


def _yaml_loader_status(sink: SinkCall) -> str:
    """Classify the loader of a ``yaml.load`` call: safe, unsafe, or unknown."""
    if sink.call.callee_text.rpartition(".")[2] != "load":
        return "not-yaml-load"
    masked = mask_strings(sink.call_text)
    match = _LOADER_KWARG_RE.search(masked)
    if match is None:
        return "unknown"
    loader = match.group(1)
    if any(safe in loader for safe in YAML_SAFE_LOADERS):
        return "safe"
    if any(unsafe in loader for unsafe in YAML_UNSAFE_LOADERS):
        return "unsafe"
    return "unknown"


def _origin_phrase(origin: Origin) -> str:
    if origin is Origin.EXTERNAL:
        return "externally influenced input"
    if origin is Origin.UNRESOLVED:
        return "input whose origin could not be resolved"
    return "configurable input"


def _arbitrary_code_mechanism(callee: str) -> bool:
    lowered = callee.lower()
    if "shelve" in lowered:
        return False
    return "pickle" in lowered or "marshal" in lowered or "unsafe_load" in lowered


def evaluate_sink(sink: SinkCall) -> EvaluatedSink | None:
    """Evaluate one candidate deserialization call (None = no finding)."""
    if not sink.first_arg.strip():
        return None
    loader_status = _yaml_loader_status(sink)
    if loader_status == "safe":
        return None
    info = sink.first_info
    if not info.is_dynamic:
        # Fixed local constant: demonstrably not attacker-controlled input.
        return None
    origins = [sink.assignments.origin_of(name, sink.call.function_id) for name in info.identifiers]
    worst = worst_origin(origins) if origins else Origin.UNRESOLVED
    if worst is Origin.CONSTANT:
        return None
    if worst is Origin.EXTERNAL:
        if _arbitrary_code_mechanism(sink.call.callee_text):
            severity = Severity.CRITICAL
        else:
            severity = Severity.HIGH
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
    loader_note = ""
    if loader_status == "unknown" and sink.call.callee_text.endswith("yaml.load"):
        loader_note = " No safe loader is visible, so the loader is treated as unresolved. "
    description = (
        f"Potential unsafe deserialization: {_origin_phrase(worst)} ({names}) "
        f"reaches the deserialization sink `{sink.call.callee_text}` via "
        f"{_mechanism(sink.call.callee_text)}.{loader_note} The mechanism can "
        "construct arbitrary objects, so untrusted serialized data deserves "
        "review. Evidence basis: "
        f"{basis}. This pattern deserves security review; it is not a "
        "confirmed vulnerability."
    )
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="Potential unsafe deserialization of untrusted data",
        description=description,
        subject_key=subject_key(sink.call.callee_text, info.identifiers),
        severity_factors=(
            f"object-constructing mechanism: {sink.call.callee_text}",
            f"origin: {worst.value}",
        ),
        confidence_factors=(f"origin category: {worst.value}", f"evidence basis: {basis}"),
        impact=(
            "If the data can be attacker-controlled, deserialization can result "
            "in arbitrary code execution or unintended object construction."
        ),
    )


def execute_unsafe_deserialization(
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
