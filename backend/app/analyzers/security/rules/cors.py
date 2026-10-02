"""SEC-INSECURE-CORS: potentially insecure CORS configuration (TASK-105).

Flags clearly insecure CORS configuration: wildcard origins in
FastAPI/Starlette CORSMiddleware or CORS response headers assigned in
code, especially combined with credential allowance. Explicit finite
origin allowlists are never reported; a wildcard alone never exceeds
Low severity; unresolved origin configuration stays unresolved. A
wildcard is never equated with a vulnerability.
"""

from __future__ import annotations

import re

from app.analyzers.findings import Confidence, Finding, Severity
from app.analyzers.rules import RuleExecutionContext, RuleOutcome
from app.analyzers.security.common import (
    EvaluatedSink,
    SinkCall,
    adjust_for_partial,
    collect_sink_calls,
    evidence_basis,
    make_location_finding,
    merge_extra_findings,
    run_rule_with_sinks,
    subject_key,
)
from app.analyzers.security.coverage import Coverage
from app.analyzers.security.flow import Origin, worst_origin
from app.analyzers.security.metadata import INSECURE_CORS_SPEC
from app.analyzers.security.sinks import CORS_MIDDLEWARE_SINKS, callee_matches
from app.analyzers.security.source import SourceProvider, mask_strings, structure_mask

SPEC = INSECURE_CORS_SPEC

_ALLOW_ORIGINS_RE = re.compile(r"\ballow_origins\s*=")
_ALLOW_CREDENTIALS_TRUE_RE = re.compile(r"\ballow_credentials\s*=\s*True\b")
_ALLOW_METHODS_WILDCARD_RE = re.compile(r"\ballow_methods\s*=\s*\[[^\]]*['\"][*]['\"][^\]]*\]")
_WILDCARD_LITERAL_RE = re.compile(r"""['"]\s*\*\s*['"]""")
_CORS_HEADER_RE = re.compile(r"Access-Control-Allow-Origin")
_CREDENTIALS_HEADER_RE = re.compile(r"Access-Control-Allow-Credentials", re.IGNORECASE)
_REQUEST_ORIGIN_RE = re.compile(r"\brequest\b", re.IGNORECASE)
_FRAMEWORK_IMPORT_RE = re.compile(r"fastapi|starlette", re.IGNORECASE)


def _matcher(callee: str, import_targets: frozenset[str]) -> bool:
    return callee_matches(callee, CORS_MIDDLEWARE_SINKS, import_targets)


def _framework_recognized(import_targets: frozenset[str]) -> bool:
    return any(_FRAMEWORK_IMPORT_RE.search(target) for target in import_targets)


def _origins_argument(call_text: str) -> str | None:
    """Extract the ``allow_origins=...`` value (list literal or bare name)."""
    masked = structure_mask(call_text)
    match = _ALLOW_ORIGINS_RE.search(masked)
    if match is None:
        return None
    # structure_mask preserves length, so masked offsets index raw text.
    raw = call_text[match.end() :].lstrip()
    if raw.startswith("["):
        depth = 0
        for position, char in enumerate(mask_strings(raw)):
            if char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
                if depth == 0:
                    return raw[: position + 1]
        return raw
    name_match = re.match(r"[A-Za-z_][A-Za-z0-9_.]*", raw)
    return name_match.group(0) if name_match else None


def evaluate_sink(sink: SinkCall) -> EvaluatedSink | None:
    """Evaluate one CORSMiddleware call (None = no finding)."""
    if sink.call.callee_text.rpartition(".")[2] == "add_middleware":
        if "CORSMiddleware" not in sink.call_text:
            # Another middleware (e.g. TrustedHostMiddleware): not CORS.
            return None
    origins_arg = _origins_argument(sink.call_text)
    if origins_arg is None:
        # No origins configured: restrictive default, nothing to report.
        return None
    recognized = _framework_recognized(sink.import_targets)
    credentials = bool(_ALLOW_CREDENTIALS_TRUE_RE.search(mask_strings(sink.call_text)))
    methods_wildcard = bool(_ALLOW_METHODS_WILDCARD_RE.search(sink.call_text))
    if origins_arg.lstrip().startswith("["):
        if not _WILDCARD_LITERAL_RE.search(origins_arg):
            # Explicit finite allowlist: never reported.
            return None
        return _wildcard_finding(
            sink,
            credentials=credentials,
            methods_wildcard=methods_wildcard,
            recognized=recognized,
            how="a wildcard origin list",
        )
    origin = sink.assignments.origin_of(origins_arg, sink.call.function_id)
    if origin is Origin.CONSTANT:
        rhs = sink.assignments.facts.get(origins_arg) or ""
        if _WILDCARD_LITERAL_RE.search(rhs):
            return _wildcard_finding(
                sink,
                credentials=credentials,
                methods_wildcard=methods_wildcard,
                recognized=recognized,
                how="a wildcard origin list referenced by name",
            )
        return None
    return _unresolved_origins_finding(sink, origins_arg, credentials, recognized)


def _cap_unrecognized(confidence: Confidence, recognized: bool) -> Confidence:
    if not recognized and confidence is Confidence.HIGH:
        return Confidence.MEDIUM
    return confidence


def _wildcard_finding(
    sink: SinkCall, *, credentials: bool, methods_wildcard: bool, recognized: bool, how: str
) -> EvaluatedSink:
    if credentials:
        severity, confidence = Severity.MEDIUM, Confidence.HIGH
        combo = " combined with credential allowance"
    else:
        severity, confidence = Severity.LOW, Confidence.MEDIUM
        combo = ""
    confidence = _cap_unrecognized(confidence, recognized)
    confidence = adjust_for_partial(confidence, sink.partial)
    factors = [f"wildcard origins ({how})"]
    if credentials:
        factors.append("allow_credentials=True")
    if methods_wildcard:
        factors.append('allow_methods=["*"]')
    description = (
        "Potentially insecure CORS configuration: "
        f"{how} is configured at `{sink.call.callee_text}`{combo}. "
        + (
            "Broad cross-origin access with credentials deserves particular review. "
            if credentials
            else ""
        )
        + ("Wildcard methods broaden the exposure further. " if methods_wildcard else "")
        + (
            "The middleware framework was not recognized, so this rests on "
            "the middleware name alone. "
            if not recognized
            else ""
        )
        + "This pattern deserves security review; it is not a confirmed "
        "vulnerability."
    )
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="Potentially insecure CORS wildcard configuration",
        description=description,
        subject_key=subject_key(sink.call.callee_text, ("allow-origins",)),
        severity_factors=tuple(factors),
        confidence_factors=("explicit origin configuration", "evidence basis: pattern"),
        impact=(
            "A permissive configuration combined with credential access may "
            "allow a malicious site to read authenticated responses on behalf "
            "of a user."
        ),
    )


def _unresolved_origins_finding(
    sink: SinkCall, name: str, credentials: bool, recognized: bool
) -> EvaluatedSink:
    confidence = adjust_for_partial(Confidence.LOW, sink.partial)
    if not recognized:
        confidence = Confidence.LOW
    description = (
        "Potentially insecure CORS configuration: the origin list at "
        f"`{sink.call.callee_text}` comes from `{name}`, whose contents "
        "could not be established statically, so a wildcard cannot be ruled "
        "out. "
        + (
            "Credentials are also allowed, which deserves particular review. "
            if credentials
            else ""
        )
        + "This pattern deserves security review; it is not a confirmed "
        "vulnerability."
    )
    return EvaluatedSink(
        severity=Severity.INFO,
        confidence=confidence,
        title="CORS origin configuration could not be resolved",
        description=description,
        subject_key=subject_key(sink.call.callee_text, ("unresolved-origins",)),
        severity_factors=("unresolved origin list",),
        confidence_factors=("origin category: unresolved", "evidence basis: pattern"),
        impact=(
            "If the unresolved list contains a wildcard with credentials, a "
            "malicious site could read authenticated responses."
        ),
    )


def _header_findings(
    execution_context: RuleExecutionContext, source: SourceProvider | None
) -> list[Finding]:
    """Flag CORS response-header assignments visible in call text (NCM-driven)."""
    if source is None:
        return []
    context = execution_context.context
    findings: list[Finding] = []
    for entry in sorted(context.ncm.files, key=lambda item: item.path):
        module = entry.module
        if module is None or (module.language or "").lower() != "python":
            continue
        source_file = source.read(entry.path)
        if source_file is None:
            continue
        partial = module.completeness != "fully"
        calls, _ = collect_sink_calls(module, source_file, lambda _callee, _imports: True)
        for sink in calls:
            if not _CORS_HEADER_RE.search(sink.call_text):
                continue
            verdict = _evaluate_header_sink(sink)
            if verdict is None:
                continue
            findings.append(
                make_location_finding(
                    spec=SPEC,
                    analyzer_version=context.analyzer_version,
                    rule_set_version=context.rule_set_version,
                    analysis_id=context.analysis_id,
                    location=sink.call.location,
                    lines=source_file.lines,
                    verdict=verdict,
                    partial=partial,
                )
            )
    return findings


def _evaluate_header_sink(sink: SinkCall) -> EvaluatedSink | None:
    """Evaluate one call mentioning Access-Control-Allow-Origin."""
    text = sink.call_text
    credentials = bool(_CREDENTIALS_HEADER_RE.search(sink.scope_text))
    if _WILDCARD_LITERAL_RE.search(text):
        if credentials:
            severity, confidence = Severity.MEDIUM, Confidence.HIGH
        else:
            severity, confidence = Severity.LOW, Confidence.MEDIUM
        basis = "pattern"
        shape = "a wildcard origin header"
    else:
        value = _header_value_region(text)
        if value is None:
            return None
        if _value_is_specific_origin(value):
            # A fixed, specific origin is restrictive: never reported.
            return None
        value_origins = [
            sink.assignments.origin_of(name, sink.call.function_id)
            for name in _region_identifiers(value)
        ]
        worst = worst_origin(value_origins) if value_origins else Origin.UNRESOLVED
        if worst is Origin.CONSTANT:
            return None
        if worst is Origin.EXTERNAL or _REQUEST_ORIGIN_RE.search(structure_mask(value)):
            if credentials:
                severity, confidence = Severity.HIGH, Confidence.HIGH
            else:
                severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
            shape = "a request-reflected origin header"
        else:
            severity, confidence = Severity.INFO, Confidence.LOW
            shape = "an origin header whose value could not be resolved"
        basis = evidence_basis(_region_identifiers(value), sink)
    confidence = adjust_for_partial(confidence, sink.partial)
    description = (
        "Potentially insecure CORS configuration: "
        f"{shape} is assigned at `{sink.call.callee_text}`"
        + (" with credential allowance visible nearby." if credentials else ".")
        + f" Evidence basis: {basis}. This pattern deserves security review; "
        "it is not a confirmed vulnerability."
    )
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="Potentially insecure CORS response header",
        description=description,
        subject_key=subject_key(sink.call.callee_text, ("acao-header",)),
        severity_factors=(shape,),
        confidence_factors=(f"evidence basis: {basis}",),
        impact=(
            "A permissive origin combined with credential access may allow a "
            "malicious site to read authenticated responses on behalf of a user."
        ),
    )


def _header_value_region(call_text: str) -> str | None:
    """Source text after the header-name literal (the assigned value)."""
    match = _CORS_HEADER_RE.search(call_text)
    if match is None:
        return None
    return call_text[match.end() :]


def _value_is_specific_origin(value: str) -> bool:
    """True when the value starts with a fixed, non-wildcard origin string."""
    rest = value.lstrip()
    if rest.startswith(","):
        rest = rest[1:].lstrip()
    literal = re.match(r"""['"]([^'"]*)['"]""", rest)
    if literal is None:
        return False
    return "*" not in literal.group(1) and "request" not in literal.group(1).lower()


def _region_identifiers(value: str) -> tuple[str, ...]:
    masked = structure_mask(value)
    return tuple(
        dict.fromkeys(
            name
            for name in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", masked)
            if name not in ("Access", "Control", "Allow", "Origin")
        )
    )


def execute_insecure_cors(
    execution_context: RuleExecutionContext, source: SourceProvider | None
) -> tuple[RuleOutcome, Coverage]:
    """Rule entry point (returns outcome plus explicit coverage)."""
    outcome, coverage = run_rule_with_sinks(
        spec=SPEC,
        execution_context=execution_context,
        source=source,
        matcher=_matcher,
        evaluate=evaluate_sink,
    )
    extra = _header_findings(execution_context, source)
    return merge_extra_findings(
        spec=SPEC,
        execution_context=execution_context,
        outcome=outcome,
        coverage=coverage,
        extra=extra,
    )
