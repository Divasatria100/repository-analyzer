"""SEC-SSRF: potential server-side request forgery (TASK-100).

Flags outbound HTTP/network request sinks whose URL (or host) is built
from externally influenced or unresolved input. Fixed constant URLs are
not reported; configurable URLs are reported at most at Info severity
with Low confidence. Requests are never sent by the analyzer.
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
from app.analyzers.security.metadata import SSRF_SPEC
from app.analyzers.security.sinks import SSRF_SINKS, callee_matches
from app.analyzers.security.source import SourceProvider, mask_strings

SPEC = SSRF_SPEC

_ALLOWLIST_RE = re.compile(r"allow[_-]?list|allowed_hosts|allow_list|ALLOWED|trusted_hosts")
_FIXED_HOST_RE = re.compile(r"""^\s*(?:[fF][rR]?|[rR][fF]?)?['\"]https?://[^'"]+['\"]""")


def _matcher(callee: str, import_targets: frozenset[str]) -> bool:
    return callee_matches(callee, SSRF_SINKS, import_targets)


def _has_visible_allowlist(scope_text: str, identifiers: tuple[str, ...]) -> bool:
    if not _ALLOWLIST_RE.search(scope_text):
        return False
    lowered = scope_text.lower()
    return any(name.lower() in lowered for name in identifiers) or "host" in lowered


def _fixed_host_with_dynamic_tail(first_arg: str) -> bool:
    masked = mask_strings(first_arg.strip())
    if not _FIXED_HOST_RE.match(masked):
        return False
    remainder = _FIXED_HOST_RE.sub("", masked).strip()
    return bool(remainder)


def evaluate_sink(sink: SinkCall) -> EvaluatedSink | None:
    """Evaluate one candidate HTTP request sink (None = no finding)."""
    if not sink.first_arg.strip():
        return None
    info = sink.first_info
    if not info.is_dynamic:
        # Fixed constant URL: not reported.
        return None
    if _has_visible_allowlist(sink.scope_text, info.identifiers):
        return None
    origins = [sink.assignments.origin_of(name, sink.call.function_id) for name in info.identifiers]
    worst = worst_origin(origins) if origins else Origin.UNRESOLVED
    if worst is Origin.CONSTANT:
        return None
    names = ", ".join(info.identifiers[:3]) if info.identifiers else "dynamic expression"
    basis = evidence_basis(info.identifiers, sink)
    if worst is Origin.CONFIGURABLE:
        severity, confidence = Severity.INFO, Confidence.LOW
        shape = "a configurable URL"
    elif _fixed_host_with_dynamic_tail(sink.first_arg):
        severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
        shape = "a fixed host with a dynamically built path or query part"
    elif worst is Origin.EXTERNAL:
        severity, confidence = Severity.HIGH, Confidence.HIGH
        shape = "an externally influenced URL"
    else:
        severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
        shape = "a URL whose origin could not be resolved"
    confidence = adjust_for_partial(confidence, sink.partial)
    description = (
        f"Potential SSRF: {shape} ({names}) reaches the outbound HTTP sink "
        f"`{sink.call.callee_text}` with no visible host restriction in the "
        f"local scope. Evidence basis: {basis}. This pattern deserves "
        "security review; it is not a confirmed vulnerability, and no request "
        "was sent."
    )
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="Potential SSRF in dynamically built request URL",
        description=description,
        subject_key=subject_key(sink.call.callee_text, info.identifiers),
        severity_factors=(f"url shape: {shape}", f"origin: {worst.value}"),
        confidence_factors=(f"origin category: {worst.value}", f"evidence basis: {basis}"),
        impact=(
            "If an attacker can control the URL, the server could be induced "
            "to reach internal services, metadata endpoints, or other "
            "resources not intended to be reachable."
        ),
    )


def execute_ssrf(
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
