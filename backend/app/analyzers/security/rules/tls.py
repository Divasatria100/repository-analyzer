"""SEC-DISABLED-TLS: disabled or weakened TLS verification (TASK-104).

Flags explicit TLS verification disabling in recognized Python APIs:
``verify=False`` on HTTP-client calls, ``session.verify = False``,
unverified SSL contexts, ``CERT_NONE``, disabled hostname checking, and
obsolete protocol versions. Similarly named options in unrecognized APIs
are never reported; normal HTTPS requests, ``verify=True``, and default
contexts are never reported. Requests are never sent.
"""

from __future__ import annotations

import re

from app.analyzers.findings import Confidence, Finding, Severity
from app.analyzers.rules import RuleExecutionContext, RuleOutcome
from app.analyzers.security.common import (
    EvaluatedSink,
    SinkCall,
    adjust_for_partial,
    evidence_basis,
    make_location_finding,
    merge_extra_findings,
    run_rule_with_sinks,
    subject_key,
)
from app.analyzers.security.coverage import Coverage
from app.analyzers.security.flow import Origin
from app.analyzers.security.metadata import DISABLED_TLS_SPEC
from app.analyzers.security.sinks import TLS_CALL_SINKS, callee_matches
from app.analyzers.security.source import SourceProvider, mask_strings, structure_mask

SPEC = DISABLED_TLS_SPEC

_VERIFY_FALSE_RE = re.compile(r"\bverify\s*=\s*False\b")
_VERIFY_TRUE_RE = re.compile(r"\bverify\s*=\s*True\b")
_VERIFY_KWARG_RE = re.compile(r"\bverify\s*=\s*([^\s,)]+)")
_SSL_FALSE_RE = re.compile(r"\bssl\s*=\s*False\b")
_CERT_NONE_RE = re.compile(r"\bCERT_NONE\b")
_OBSOLETE_PROTOCOL_RE = re.compile(r"\bPROTOCOL_(SSLv2|SSLv3|TLSv1|TLSv1_1)\b")
_UNVERIFIED_CONTEXT_RE = re.compile(r"_create_unverified_context\s*\(")

#: Receivers whose ``.verify`` attribute is a TLS setting in recognized APIs.
_SESSION_RECEIVERS = frozenset({"session", "sess", "client", "http", "api"})

#: Receivers whose ``.check_hostname``/``.verify_mode`` is an SSL setting.
_CONTEXT_RECEIVERS = frozenset({"ctx", "context", "ssl_context", "sslcontext"})
_TLS_IMPORT_HINTS = frozenset({"requests", "httpx", "urllib3", "aiohttp", "ssl"})

#: Assignment attributes that weaken TLS, with the insecure RHS each needs.
_TLS_ASSIGNMENTS = (
    ("verify", re.compile(r"^\s*False\s*(#.*)?$")),
    ("check_hostname", re.compile(r"^\s*False\s*(#.*)?$")),
    ("verify_mode", re.compile(r"^\s*(ssl\.)?CERT_NONE\s*(#.*)?$")),
)


def _matcher(callee: str, import_targets: frozenset[str]) -> bool:
    return callee_matches(callee, TLS_CALL_SINKS, import_targets)


def _recognized_tls_imports(import_targets: frozenset[str]) -> bool:
    return any(
        target == hint or target.startswith(hint + ".") or hint in target
        for hint in _TLS_IMPORT_HINTS
        for target in import_targets
    )


def _resolve_verify_value(sink: SinkCall, token: str) -> str:
    """Resolve a ``verify=<token>`` value: false, true, or unresolved."""
    normalized = token.strip().strip(",")
    if normalized == "False":
        return "false"
    if normalized == "True":
        return "true"
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", normalized):
        return "unresolved"
    origin = sink.assignments.origin_of(normalized, sink.call.function_id)
    if origin is Origin.CONSTANT:
        rhs = (sink.assignments.facts.get(normalized) or "").strip()
        if rhs == "False":
            return "false"
        if rhs == "True":
            return "true"
        return "unresolved"
    return "unresolved"


def evaluate_sink(sink: SinkCall) -> EvaluatedSink | None:
    """Evaluate one candidate TLS call (None = no finding)."""
    # String contents are masked so tokens inside string arguments
    # (e.g. data="verify=False") can never trigger a finding.
    masked = mask_strings(sink.call_text)
    if _UNVERIFIED_CONTEXT_RE.search(masked):
        return _unverified_context_finding(sink)
    if _CERT_NONE_RE.search(masked):
        return _cert_none_finding(sink)
    obsolete = _OBSOLETE_PROTOCOL_RE.search(masked)
    if obsolete:
        return _obsolete_protocol_finding(sink, obsolete.group(0))
    if _SSL_FALSE_RE.search(masked):
        return _ssl_false_finding(sink)
    match = _VERIFY_KWARG_RE.search(masked)
    if match is None:
        return None
    resolved = _resolve_verify_value(sink, match.group(1))
    if resolved == "true":
        return None
    if resolved == "false":
        return _verify_disabled_finding(sink, conditional=False)
    return _verify_disabled_finding(sink, conditional=True)


def _url_is_dynamic(sink: SinkCall) -> bool:
    return sink.first_info.is_dynamic and bool(sink.first_arg.strip())


def _verify_disabled_finding(sink: SinkCall, conditional: bool) -> EvaluatedSink:
    if conditional:
        severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
        setting = "a `verify` value the analyzer could not resolve statically"
    else:
        severity = Severity.HIGH if _url_is_dynamic(sink) else Severity.MEDIUM
        confidence = Confidence.HIGH
        setting = "an explicit `verify=False`"
    confidence = adjust_for_partial(confidence, sink.partial)
    basis = "pattern" if conditional else evidence_basis((), sink)
    description = (
        "TLS certificate verification appears disabled: "
        f"{setting} reaches the recognized HTTP client `{sink.call.callee_text}`. "
        "Evidence basis: "
        f"{basis}. This pattern deserves security review; it is not a "
        "confirmed vulnerability, and no request was sent."
    )
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="TLS certificate verification appears disabled",
        description=description,
        subject_key=subject_key(sink.call.callee_text, ("verify-false",)),
        severity_factors=("explicit verify disabling",),
        confidence_factors=(f"setting: {'unresolved' if conditional else 'literal False'}",),
        impact=(
            "If the code runs against real endpoints, it may accept forged "
            "certificates, allowing interception or modification of traffic."
        ),
    )


def _unverified_context_finding(sink: SinkCall) -> EvaluatedSink:
    confidence = adjust_for_partial(Confidence.HIGH, sink.partial)
    return EvaluatedSink(
        severity=Severity.MEDIUM,
        confidence=confidence,
        title="Unverified TLS context is created",
        description=(
            "An explicitly unverified TLS context is created at "
            f"`{sink.call.callee_text}`. Evidence basis: pattern (explicit "
            "insecure constructor). This pattern deserves security review; it "
            "is not a confirmed vulnerability."
        ),
        subject_key=subject_key(sink.call.callee_text, ("unverified-context",)),
        severity_factors=("explicit unverified context",),
        confidence_factors=("explicit insecure constructor",),
        impact="Connections using this context accept any certificate without verification.",
    )


def _cert_none_finding(sink: SinkCall) -> EvaluatedSink:
    confidence = adjust_for_partial(Confidence.HIGH, sink.partial)
    return EvaluatedSink(
        severity=Severity.MEDIUM,
        confidence=confidence,
        title="TLS verification disabled via CERT_NONE",
        description=(
            "Certificate verification is set to `CERT_NONE` at "
            f"`{sink.call.callee_text}`, disabling verification. Evidence "
            "basis: pattern (explicit insecure constant). This pattern "
            "deserves security review; it is not a confirmed vulnerability."
        ),
        subject_key=subject_key(sink.call.callee_text, ("cert-none",)),
        severity_factors=("CERT_NONE verification mode",),
        confidence_factors=("explicit insecure constant",),
        impact="Connections accept any certificate without verification.",
    )


def _obsolete_protocol_finding(sink: SinkCall, protocol: str) -> EvaluatedSink:
    confidence = adjust_for_partial(Confidence.MEDIUM, sink.partial)
    return EvaluatedSink(
        severity=Severity.MEDIUM,
        confidence=confidence,
        title="Obsolete TLS protocol version is configured",
        description=(
            f"An obsolete protocol version ({protocol}) is configured "
            f"explicitly at `{sink.call.callee_text}`. Evidence basis: pattern "
            "(explicit protocol constant). This pattern deserves security "
            "review; it is not a confirmed vulnerability."
        ),
        subject_key=subject_key(sink.call.callee_text, (protocol.lower(),)),
        severity_factors=(f"obsolete protocol: {protocol}",),
        confidence_factors=("explicit protocol constant",),
        impact="Obsolete protocol versions lack modern security guarantees.",
    )


def _ssl_false_finding(sink: SinkCall) -> EvaluatedSink:
    confidence = adjust_for_partial(Confidence.HIGH, sink.partial)
    return EvaluatedSink(
        severity=Severity.MEDIUM,
        confidence=confidence,
        title="TLS disabled on an HTTP connector",
        description=(
            "TLS is disabled explicitly (`ssl=False`) at "
            f"`{sink.call.callee_text}`. Evidence basis: pattern (explicit "
            "insecure setting). This pattern deserves security review; it is "
            "not a confirmed vulnerability, and no request was sent."
        ),
        subject_key=subject_key(sink.call.callee_text, ("ssl-false",)),
        severity_factors=("explicit ssl=False",),
        confidence_factors=("explicit insecure setting",),
        impact="Traffic through this connector is not protected by TLS.",
    )


def _assignment_rhs(line: str) -> str:
    masked = structure_mask(line)
    equals = masked.find("=")
    if equals == -1:
        return ""
    return line[equals + 1 :].strip()


def _ssl_imported(import_targets: frozenset[str]) -> bool:
    return any(target == "ssl" or target.startswith("ssl.") for target in import_targets)


def _assignment_findings(
    execution_context: RuleExecutionContext, source: SourceProvider | None
) -> list[Finding]:
    """Flag ``session.verify = False``-style attribute assignments (NCM-driven)."""
    if source is None:
        return []
    context = execution_context.context
    findings: list[Finding] = []
    for entry in sorted(context.ncm.files, key=lambda item: item.path):
        module = entry.module
        if module is None or (module.language or "").lower() != "python":
            continue
        import_targets = frozenset(imp.target_text for imp in module.imports)
        recognized = _recognized_tls_imports(import_targets)
        source_file = source.read(entry.path)
        if source_file is None:
            continue
        lines = list(source_file.lines)
        partial = module.completeness != "fully"
        for assignment in module.assignments:
            if assignment.location is None or not assignment.target_names:
                continue
            for target in assignment.target_names:
                if "." not in target:
                    # Bare names (e.g. a module-level flag) are evaluated at
                    # their use site instead of at the assignment.
                    continue
                attribute = target.rpartition(".")[2]
                receiver = target.rpartition(".")[0].rpartition(".")[2]
                for insecure_attr, rhs_pattern in _TLS_ASSIGNMENTS:
                    if attribute != insecure_attr:
                        continue
                    if attribute == "verify":
                        if receiver not in _SESSION_RECEIVERS and not recognized:
                            continue
                    elif receiver not in _CONTEXT_RECEIVERS and not _ssl_imported(import_targets):
                        continue
                    lineno = assignment.location.start_line
                    if lineno < 1 or lineno > len(lines):
                        continue
                    if not rhs_pattern.match(_assignment_rhs(lines[lineno - 1])):
                        continue
                    confidence = adjust_for_partial(Confidence.HIGH, partial)
                    findings.append(
                        make_location_finding(
                            spec=SPEC,
                            analyzer_version=context.analyzer_version,
                            rule_set_version=context.rule_set_version,
                            analysis_id=context.analysis_id,
                            location=assignment.location,
                            lines=source_file.lines,
                            verdict=EvaluatedSink(
                                severity=Severity.MEDIUM,
                                confidence=confidence,
                                title="TLS certificate verification appears disabled",
                                description=(
                                    f"TLS verification is disabled explicitly via "
                                    f"`{target} = ...` with an insecure value. "
                                    "Evidence basis: pattern (explicit insecure "
                                    "assignment). This pattern deserves security "
                                    "review; it is not a confirmed vulnerability."
                                ),
                                subject_key=subject_key(target, (insecure_attr,)),
                                severity_factors=("explicit verify disabling",),
                                confidence_factors=("explicit insecure assignment",),
                                impact=(
                                    "Clients using this setting may accept forged "
                                    "certificates, allowing interception of traffic."
                                ),
                            ),
                            partial=partial,
                        )
                    )
    return findings


def execute_disabled_tls(
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
    extra = _assignment_findings(execution_context, source)
    return merge_extra_findings(
        spec=SPEC,
        execution_context=execution_context,
        outcome=outcome,
        coverage=coverage,
        extra=extra,
    )
