"""SEC-WEAK-CRYPTO: potential weak cryptography (TASK-103).

Flags clearly weak cryptographic primitives where the API usage itself
provides strong evidence: MD5/SHA-1 hashing, DES/3DES/RC4 ciphers, ECB
cipher mode, and non-cryptographic randomness used for secrets. Purpose
context (password handling vs checksums) drives severity and confidence;
comments, variable names, and string-only mentions can never trigger a
finding because detection starts from NCM call sites, never text search.
Ambiguous purpose lowers confidence and always requires manual review.
"""

from __future__ import annotations

import re

from app.analyzers.findings import Confidence, Severity
from app.analyzers.rules import RuleExecutionContext, RuleOutcome
from app.analyzers.security.common import (
    EvaluatedSink,
    SinkCall,
    adjust_for_partial,
    run_rule_with_sinks,
    subject_key,
)
from app.analyzers.security.coverage import Coverage
from app.analyzers.security.metadata import WEAK_CRYPTO_SPEC
from app.analyzers.security.sinks import (
    CRYPTO_SINKS,
    RANDOM_SINKS,
    STRONG_HASH_NAMES,
    WEAK_HASH_NAMES,
    callee_matches,
)
from app.analyzers.security.source import SourceProvider, mask_strings, structure_mask

SPEC = WEAK_CRYPTO_SPEC

_SENSITIVE_PURPOSE_RE = re.compile(
    r"password|passwd|pwd|secret|private|credential|authenticate|hmac|signature|"
    r"\bsign\b|token|user_?pass|\bauth\b",
    re.IGNORECASE,
)
_NON_SECURITY_PURPOSE_RE = re.compile(
    r"checksum|\bcache\b|etag|dedup|usedforsecurity\s*=\s*False",
    re.IGNORECASE,
)
_USEDFORSECURITY_FALSE_RE = re.compile(r"usedforsecurity\s*=\s*False", re.IGNORECASE)
_MODE_ECB_RE = re.compile(r"\bMODE_ECB\b|\bECB\b")
_NEW_LITERAL_RE = re.compile(r"""^\s*['"]([A-Za-z0-9_+\-]+)['"]""")
_SENSITIVE_TARGET_RE = re.compile(
    r"token|secret|passwd|password|pwd|nonce|salt|otp|credential|private|auth|"
    r"api[_-]?key|\bkey\b|secret[_-]?key|session[_-]?(id|key|token)",
    re.IGNORECASE,
)
_TARGET_ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*$")
_PREFIX_ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?<![=!<>])=(?![=>])")
_WEAK_CIPHER_RE = re.compile(r"DES3?|ARC4|ARC2|RC4|MD5|SHA1|\bSHA\b", re.IGNORECASE)
_STRONG_CIPHER_RE = re.compile(r"SHA(256|512|384|224|3_)|BLAKE|AES|ChaCha|Poly1305", re.IGNORECASE)


def _matcher(callee: str, import_targets: frozenset[str]) -> bool:
    return callee_matches(callee, CRYPTO_SINKS, import_targets) or callee_matches(
        callee, RANDOM_SINKS, import_targets
    )


def _purpose(sink: SinkCall) -> str:
    """Infer purpose: security-sensitive, non-security, or ambiguous."""
    if _USEDFORSECURITY_FALSE_RE.search(sink.call_text):
        return "non-security"
    haystacks = [
        " ".join(sink.first_info.identifiers),
        sink.function.qualified_name if sink.function is not None else "",
        sink.scope_text,
    ]
    sensitive = any(_SENSITIVE_PURPOSE_RE.search(text) for text in haystacks)
    benign = any(_NON_SECURITY_PURPOSE_RE.search(text) for text in haystacks)
    if sensitive and not benign:
        return "security"
    if benign and not sensitive:
        return "non-security"
    if sensitive and benign:
        return "ambiguous"
    return "ambiguous"


def _new_algorithm(first_arg: str) -> str | None:
    """Extract the algorithm literal from ``hashlib.new(...)``, if static."""
    match = _NEW_LITERAL_RE.match(first_arg.strip())
    return match.group(1).lower() if match else None


def _random_target(sink: SinkCall) -> str | None:
    """Sensitive assignment target receiving the random call, if any.

    Covers both direct assignment on the sink line and calls nested in a
    larger right-hand side recorded in the local assignment map.
    """
    lines = sink.source.lines if sink.source is not None else ()
    lineno = sink.call.location.start_line
    column = sink.call.location.start_column
    if lines and 1 <= lineno <= len(lines):
        # Masked so `=` inside string literals cannot fake an assignment.
        prefix = structure_mask(lines[lineno - 1][:column])
        match = _TARGET_ASSIGN_RE.search(prefix) or _PREFIX_ASSIGN_RE.search(prefix)
        if match is not None:
            return match.group(1)
    base = sink.call.callee_text.rpartition(".")[2]
    for name in sorted(sink.assignments.facts):
        rhs = sink.assignments.facts[name]
        if re.search(r"\brandom\s*\.\s*" + re.escape(base) + r"\s*\(", rhs):
            return name
    return None


def _manual_review_suffix() -> str:
    return " Manual review is required to confirm the purpose."


def evaluate_sink(sink: SinkCall) -> EvaluatedSink | None:
    """Evaluate one candidate crypto call (None = no finding)."""
    callee = sink.call.callee_text
    base = callee.rpartition(".")[2]
    lowered = callee.lower()

    if "random" in lowered and base in (
        "random",
        "choice",
        "choices",
        "randint",
        "randrange",
        "uniform",
        "sample",
        "shuffle",
    ):
        return _evaluate_random(sink)
    if base == "new" and "hashlib" in lowered:
        return _evaluate_hashlib_new(sink)
    if _STRONG_CIPHER_RE.search(callee) and not _WEAK_CIPHER_RE.search(callee):
        return None
    if base == "new":
        return _evaluate_cipher_new(sink)
    if base in ("md5", "sha1") or "md5" in lowered or "sha1" in lowered:
        return _evaluate_weak_hash(sink, "MD5" if "md5" in lowered else "SHA-1")
    return None


def _evaluate_weak_hash(sink: SinkCall, algorithm: str) -> EvaluatedSink | None:
    """MD5/SHA-1 call with purpose-driven severity and confidence."""
    purpose = _purpose(sink)
    if purpose == "security":
        severity, confidence = Severity.HIGH, Confidence.HIGH
    elif purpose == "non-security":
        severity, confidence = Severity.LOW, Confidence.LOW
    else:
        severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
    confidence = adjust_for_partial(confidence, sink.partial)
    description = (
        f"Potential weak cryptography: {algorithm} is used in a "
        f"{purpose} hashing context at `{sink.call.callee_text}`. "
        f"Evidence basis: {purpose} purpose inferred from visible names and "
        f"context.{_manual_review_suffix()} This pattern deserves security "
        "review; it is not a confirmed vulnerability."
    )
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title=f"Potential weak hashing with {algorithm}",
        description=description,
        subject_key=subject_key(sink.call.callee_text, (algorithm.lower(), purpose)),
        severity_factors=(f"weak algorithm: {algorithm}", f"purpose: {purpose}"),
        confidence_factors=(f"purpose context: {purpose}", "evidence basis: context"),
        impact=(
            "Weak primitives may allow attackers to recover protected data, "
            "forge integrity guarantees, or predict values assumed to be secret."
        ),
    )


def _evaluate_hashlib_new(sink: SinkCall) -> EvaluatedSink | None:
    """``hashlib.new(name, ...)``: report only genuinely weak names."""
    algorithm = _new_algorithm(sink.first_arg)
    if algorithm is None:
        confidence = adjust_for_partial(Confidence.LOW, sink.partial)
        return EvaluatedSink(
            severity=Severity.INFO,
            confidence=confidence,
            title="Hash algorithm selected dynamically",
            description=(
                "The hash algorithm passed to `hashlib.new` could not be "
                "established statically, so weak-algorithm use cannot be ruled "
                f"out.{_manual_review_suffix()} Evidence basis: pattern."
            ),
            subject_key=subject_key(sink.call.callee_text, ("dynamic-algorithm",)),
            severity_factors=("unresolved algorithm name",),
            confidence_factors=("origin category: unresolved", "evidence basis: pattern"),
            impact="A weak algorithm selected at runtime would carry the usual weak-hash risks.",
        )
    if algorithm in STRONG_HASH_NAMES:
        return None
    if algorithm in WEAK_HASH_NAMES:
        return _evaluate_weak_hash(sink, algorithm.upper())
    return None


def _evaluate_cipher_new(sink: SinkCall) -> EvaluatedSink | None:
    """Cipher constructors: weak ciphers and ECB mode only."""
    masked_text = mask_strings(sink.call_text)
    if _MODE_ECB_RE.search(masked_text):
        confidence = adjust_for_partial(Confidence.HIGH, sink.partial)
        return EvaluatedSink(
            severity=Severity.HIGH,
            confidence=confidence,
            title="Potential weak cipher mode (ECB)",
            description=(
                f"ECB cipher mode is used explicitly at `{sink.call.callee_text}`. "
                "ECB leaks plaintext structure regardless of key strength. "
                "Evidence basis: pattern (explicit mode constant)."
            ),
            subject_key=subject_key(sink.call.callee_text, ("ecb",)),
            severity_factors=("weak mode: ECB",),
            confidence_factors=("explicit mode constant", "evidence basis: pattern"),
            impact="ECB-encrypted data may reveal plaintext patterns to an observer.",
        )
    if _WEAK_CIPHER_RE.search(sink.call.callee_text) and not _STRONG_CIPHER_RE.search(
        sink.call.callee_text
    ):
        confidence = adjust_for_partial(Confidence.HIGH, sink.partial)
        return EvaluatedSink(
            severity=Severity.HIGH,
            confidence=confidence,
            title="Potential weak cipher algorithm",
            description=(
                f"A weak cipher is constructed at `{sink.call.callee_text}`. "
                "Interoperability with legacy systems mandating this algorithm "
                "cannot be ruled out statically, but modern use deserves "
                f"review.{_manual_review_suffix()} Evidence basis: pattern "
                "(explicit cipher constructor)."
            ),
            subject_key=subject_key(sink.call.callee_text, ("weak-cipher",)),
            severity_factors=("weak cipher constructor",),
            confidence_factors=("explicit cipher constructor", "evidence basis: pattern"),
            impact="Weak ciphers may allow attackers to recover protected data.",
        )
    return None


def _evaluate_random(sink: SinkCall) -> EvaluatedSink | None:
    """stdlib ``random`` flowing into a sensitive-named value."""
    target = _random_target(sink)
    if target is None or not _SENSITIVE_TARGET_RE.search(target):
        return None
    confidence = adjust_for_partial(Confidence.HIGH, sink.partial)
    return EvaluatedSink(
        severity=Severity.MEDIUM,
        confidence=confidence,
        title="Non-cryptographic randomness used for a secret value",
        description=(
            f"The value `{target}` is built with the non-cryptographic "
            f"`random` module at `{sink.call.callee_text}`. Names indicate a "
            "secret or token, which the Mersenne Twister generator cannot "
            f"protect.{_manual_review_suffix()} Evidence basis: local "
            "relationship."
        ),
        subject_key=subject_key(sink.call.callee_text, (target,)),
        severity_factors=("non-cryptographic generator", f"sensitive target: {target}"),
        confidence_factors=("sensitive target name", "evidence basis: local relationship"),
        impact="Predictable values assumed to be secret may let attackers forge tokens or keys.",
    )


def execute_weak_crypto(
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
