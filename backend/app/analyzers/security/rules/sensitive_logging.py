"""SEC-SENSITIVE-LOGGING: sensitive information in logs (TASK-106).

Flags sensitive values passed to recognized logging APIs (stdlib
``logging`` logger/module calls) and, with reduced confidence, ``print``.
A finding rests on the relationship between a sensitive value and the
logging operation — name plus origin, sensitive attributes/fields, or
sensitive whole objects — never on logging alone. Masked, redacted,
boolean, length, or sliced representations are not reported, nor are
non-sensitive identifiers. Findings never include the sensitive value
itself (names and API shapes only).
"""

from __future__ import annotations

import re

from app.analyzers.findings import Confidence, Limitation, Severity
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
from app.analyzers.security.flow import (
    Origin,
    analyze_expression,
    classify_rhs_origin,
    worst_origin,
)
from app.analyzers.security.metadata import SENSITIVE_LOGGING_SPEC
from app.analyzers.security.sinks import LOGGING_SINKS, callee_matches
from app.analyzers.security.source import SourceProvider, structure_mask

SPEC = SENSITIVE_LOGGING_SPEC

#: Names that clearly identify credential/authorization material.
_CREDENTIAL_RE = re.compile(
    r"\b(passwords?|passwds?|secrets?|api[_-]?keys?|apikeys?|access_tokens?|refresh_tokens?|"
    r"auth_tokens?|private_keys?|client_secrets?|credentials?|authorization)\b",
    re.IGNORECASE,
)

#: Names that suggest sensitivity without proving credential material.
_SENSITIVE_NAMES_RE = re.compile(
    r"\b(tokens?|sessions?|session_tokens?|cookies?|sessionids?|auth|api_secrets?)\b",
    re.IGNORECASE,
)

#: Trailing name parts that mark measurement/presence metadata, never secrets.
_MEASUREMENT_SUFFIX_RE = re.compile(
    r"_(count|length|len|size|present|exists|valid|verified|checked|masked|redacted|hash)$",
    re.IGNORECASE,
)

#: Whole objects whose logging may expose sensitive fields.
_SENSITIVE_OBJECT_RE = re.compile(
    r"^(request|response|headers|cookies|config|settings|environ)$",
    re.IGNORECASE,
)
_ENTITY_OBJECT_RE = re.compile(
    r"^(user|account|customer|patient|employee|member|profile|order|payment)s?$",
    re.IGNORECASE,
)

#: f-string interpolation slots: {name}, {obj.attr}, {d["key"]} (+ !s / :fmt).
_FSTRING_SLOT_RE = re.compile(
    r"\{([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]{}\n]*\])?)"
    r"(?:![sr])?(?:\:[^}\n]*)?\}"
)


def _matcher(callee: str, import_targets: frozenset[str]) -> bool:
    return callee_matches(callee, LOGGING_SINKS, import_targets)


def _is_print_call(sink: SinkCall) -> bool:
    return sink.call.callee_text == "print" or sink.call.callee_text.endswith(".print")


def _strip_measurement(name: str) -> str | None:
    """Return None when a name only measures sensitivity metadata."""
    if _MEASUREMENT_SUFFIX_RE.search(name):
        return None
    return name


def _classify_name(name: str) -> str:
    """One of 'credential', 'sensitive', or 'plain' for a bare identifier."""
    lowered = name.lower()
    if _CREDENTIAL_RE.search(lowered):
        return "credential"
    if _SENSITIVE_NAMES_RE.search(lowered):
        return "sensitive"
    return "plain"


def _fstring_names(call_text: str) -> tuple[str, ...]:
    """Interpolated names inside f-string literals (raw text, strings kept)."""
    return tuple(dict.fromkeys(match.group(1) for match in _FSTRING_SLOT_RE.finditer(call_text)))


def _safe_span_covered(call_text: str, name: str) -> bool:
    """True when every occurrence of a name sits inside a safe wrapper/slice.

    Safe contexts are masking/redacting helper calls, ``bool(...)`` /
    ``len(...)`` wrappers, and numeric or slice subscripts (``token[:4]``).
    A subscript selecting a sensitive string key (``headers["Authorization"]``)
    is never safe; neither are variable subscripts.
    """
    masked = structure_mask(call_text)
    pattern = re.compile(r"\b" + re.escape(name) + r"\b")
    found = False
    for match in pattern.finditer(masked):
        found = True
        before = masked[: match.start()]
        # Raw text from the same offset: string contents are visible here,
        # so a quoted key (["Authorization"]) is distinguishable from a
        # numeric or slice subscript ([:4]).
        after_raw = call_text[match.end() :]
        wrapper = re.search(
            r"(bool|len|\w*(?:mask|redact|sanitiz|anonymiz|hide|obscure|truncate)\w*)\s*\($",
            before,
        )
        bracket = re.match(r"\s*\[", after_raw)
        if bracket is not None:
            inner = after_raw[bracket.end() :]
            if inner[:1] in ("'", '"'):
                return False
            if re.match(r"[\d\s:\-+]*\]", inner) is None:
                return False
            continue
        if wrapper is None:
            return False
    return found


#: Subscript selections ``base["key"]`` in raw call text.
_SUBSCRIPT_KEY_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*)\[\s*['\"]([^'\"\]]+)['\"]\s*\]")


def _logged_shape(sink: SinkCall) -> tuple[tuple[str, str, str], ...]:
    """Sensitive (display, base, tier) triples reaching the sink.

    Tier is ``credential`` or ``sensitive``. Provably safe occurrences
    (masked/redacted/bool/len/slice) and measurement-only names are
    excluded. Never includes values, only names.
    """
    triples: dict[str, tuple[str, str]] = {}
    for segment in [sink.first_arg, *sink.keyword_text.split("\n")]:
        if not segment.strip():
            continue
        for name in analyze_expression(segment).identifiers:
            if _strip_measurement(name) is None:
                continue
            tier = _classify_name(name)
            if tier != "plain":
                triples.setdefault(name, (name, tier))
    for dotted in _fstring_names(sink.call_text):
        base, _, attr = dotted.partition(".")
        if _strip_measurement(attr or base) is None:
            continue
        tier = _classify_name(attr or base)
        if tier != "plain":
            triples.setdefault(dotted, (base, tier))
    for match in _SUBSCRIPT_KEY_RE.finditer(sink.call_text):
        base, key = match.group(1), match.group(2)
        if _strip_measurement(key) is None:
            continue
        tier = _classify_name(key)
        if tier != "plain":
            triples.setdefault(f'{base}["{key}"]', (base, tier))
    return tuple(
        (display, base, tier)
        for display, (base, tier) in triples.items()
        if not _safe_span_covered(sink.call_text, base)
    )


def _whole_object_kind(sink: SinkCall) -> str | None:
    """'sensitive-object' / 'entity-object' for whole-object logging.

    Covers lone identifiers (``logger.info(user)``), format calls with a
    single identifier argument (``logger.info("user=%s", user)``), and
    f-strings interpolating one object (``logger.info(f"user={user}")``).
    Any other dynamic argument disqualifies the shape.
    """
    segments = [sink.first_arg, *sink.keyword_text.split("\n")]
    args = [segment.strip() for segment in segments if segment.strip()]
    candidates: list[str] = []
    for segment in args:
        info = analyze_expression(segment)
        if info.has_fstring:
            candidates.extend(_fstring_names(segment))
            continue
        if not info.identifiers:
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", segment):
            if _strip_measurement(segment) is not None:
                candidates.append(segment)
                continue
        return None
    unique = list(dict.fromkeys(name.split(".")[0] for name in candidates))
    if len(unique) != 1:
        return None
    name = unique[0]
    if _SENSITIVE_OBJECT_RE.fullmatch(name):
        return "sensitive-object"
    if _ENTITY_OBJECT_RE.fullmatch(name):
        return "entity-object"
    return None


def _triple_origin(sink: SinkCall, base: str, display: str) -> Origin:
    """Origin of one sensitive triple, preferring visible source markers.

    Dotted/subscripted bases (``request.headers["Authorization"]``) carry
    their provenance in the expression itself; the assignment walk resolves
    the leading name as a fallback.
    """
    marked = classify_rhs_origin(display)
    if marked in (Origin.EXTERNAL, Origin.CONFIGURABLE):
        return marked
    return sink.assignments.origin_of(base.split(".")[0], sink.call.function_id)


def evaluate_sink(sink: SinkCall) -> EvaluatedSink | None:
    """Evaluate one candidate logging call (None = no finding)."""
    if not sink.first_arg.strip() and not sink.keyword_text.strip():
        return None
    triples = _logged_shape(sink)
    is_print = _is_print_call(sink)
    if not triples:
        whole = _whole_object_kind(sink)
        if whole is None:
            return None
        return _object_finding(sink, whole, is_print)
    names = tuple(display for display, _, _ in triples)
    bases = tuple(base for _, base, _ in triples)
    tiers = tuple(tier for _, _, tier in triples)
    origins = [_triple_origin(sink, base, display) for display, base, _ in triples]
    worst = worst_origin(origins) if origins else Origin.UNRESOLVED
    credential = "credential" in tiers
    basis = evidence_basis(tuple(sorted(set(b.split(".")[0] for b in bases))), sink)
    shown = ", ".join(sorted(set(names))[:3])
    if is_print:
        if worst is Origin.CONSTANT:
            return None
        severity, confidence = Severity.LOW, Confidence.LOW
        shape = f"a sensitive-named value ({shown}) printed"
    elif credential and worst in (Origin.EXTERNAL, Origin.CONFIGURABLE):
        severity, confidence = Severity.HIGH, Confidence.HIGH
        shape = f"a credential value ({shown}) logged"
    elif credential:
        severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
        shape = f"a credential-named value ({shown}) logged"
    else:
        severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
        shape = f"a sensitive-named value ({shown}) logged"
    confidence = adjust_for_partial(confidence, sink.partial)
    description = (
        f"Potential sensitive data in logs: {shape} reaches the logging sink "
        f"`{sink.call.callee_text}`. Origin category: {worst.value}. Evidence "
        f"basis: {basis}. Only names and API shapes are recorded here; the "
        "logged value itself is never included. This pattern deserves "
        "security review; it is not a confirmed exposure."
    )
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="Potential sensitive data written to logs",
        description=description,
        subject_key=subject_key(sink.call.callee_text, tuple(sorted(set(names)))),
        severity_factors=(f"sensitive logging: {shown}", f"origin: {worst.value}"),
        confidence_factors=(f"origin category: {worst.value}", f"evidence basis: {basis}"),
        impact=(
            "Logs are commonly retained, aggregated, and readable by more "
            "parties than the original data. Sensitive values in logs may be "
            "exposed to those who can access them."
        ),
    )


def _object_finding(sink: SinkCall, kind: str, is_print: bool) -> EvaluatedSink | None:
    """Whole request/config/entity objects logged without field evidence."""
    if is_print:
        return None
    name = sink.first_arg.strip()
    if kind == "sensitive-object":
        severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
        shape = f"the whole object `{name}`, which may contain sensitive fields"
    else:
        severity, confidence = Severity.LOW, Confidence.LOW
        shape = f"the whole object `{name}`, which may carry sensitive fields"
    confidence = adjust_for_partial(confidence, sink.partial)
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="Potentially sensitive object written to logs",
        description=(
            f"Potential sensitive data in logs: {shape}, is passed to the "
            f"logging sink `{sink.call.callee_text}`. Only the object name is "
            "recorded here; the logged value itself is never included. Manual "
            "review is required to determine whether sensitive fields are "
            "present. This pattern deserves security review; it is not a "
            "confirmed exposure."
        ),
        subject_key=subject_key(sink.call.callee_text, (name,)),
        severity_factors=(f"whole-object logging: {name}",),
        confidence_factors=("object shape only", "evidence basis: pattern"),
        limitations=(
            Limitation(
                scope=f"security:{SPEC.rule_id}",
                reason="Only the logged object name is known; whether it "
                "carries sensitive fields could not be established.",
                path=sink.call.location.file_path,
                rule_id=SPEC.rule_id,
            ),
        ),
        impact=(
            "Logging whole request, header, or configuration objects may "
            "persist credentials or tokens readable by log viewers."
        ),
    )


def execute_sensitive_logging(
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
