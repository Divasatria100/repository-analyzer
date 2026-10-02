"""SEC-COMMAND-INJECTION: potential command injection (TASK-098).

Flags dynamically built command text reaching recognized command
execution APIs (``subprocess`` family, ``os.system``/``os.popen``),
with special attention to shell interpretation (the ``shell`` keyword
set to true). Structured argument lists executed without a shell are
treated as lower risk and not reported; fully constant commands are
reported at most at Info. Detected commands are never executed by the
analyzer.
"""

from __future__ import annotations

from app.analyzers.findings import Confidence, Severity
from app.analyzers.rules import RuleExecutionContext, RuleOutcome
from app.analyzers.security.common import (
    SHELL_FALSE_RE,
    SHELL_TRUE_RE,
    EvaluatedSink,
    SinkCall,
    adjust_for_partial,
    evidence_basis,
    run_rule_with_sinks,
    subject_key,
)
from app.analyzers.security.coverage import Coverage
from app.analyzers.security.flow import Origin, worst_origin
from app.analyzers.security.metadata import COMMAND_INJECTION_SPEC
from app.analyzers.security.sinks import COMMAND_SINKS, callee_matches, receiver_of
from app.analyzers.security.source import SourceProvider, mask_strings

SPEC = COMMAND_INJECTION_SPEC


def _matcher(callee: str, import_targets: frozenset[str]) -> bool:
    return callee_matches(callee, COMMAND_SINKS, import_targets)


def _always_shell(callee: str) -> bool:
    base = callee.rpartition(".")[2]
    return base in ("system", "popen")


def _is_list_form(first_arg: str) -> bool:
    return mask_strings(first_arg).lstrip().startswith("[")


def evaluate_sink(sink: SinkCall) -> EvaluatedSink | None:
    """Evaluate one candidate command-execution call (None = no finding)."""
    if not sink.first_arg.strip():
        return None
    shell = bool(SHELL_TRUE_RE.search(sink.call_text)) or _always_shell(sink.call.callee_text)
    explicit_no_shell = bool(SHELL_FALSE_RE.search(sink.call_text))
    list_form = _is_list_form(sink.first_arg)
    info = sink.first_info
    receiver = receiver_of(sink.call.callee_text)

    if not info.is_dynamic:
        if shell:
            return EvaluatedSink(
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                title="Constant command executed with a shell",
                description=(
                    f"A constant command reaches `{sink.call.callee_text}` with shell "
                    "interpretation. No untrusted input is visible, so this is "
                    "not a command injection pattern, but shell use deserves "
                    "review. Evidence basis: pattern."
                ),
                subject_key=f"{sink.call.callee_text}:constant-shell",
                severity_factors=("constant command text", "shell interpretation"),
                confidence_factors=("no dynamic parts visible", "evidence basis: pattern"),
                impact=(
                    "Shell interpretation of even constant commands widens the "
                    "impact if the command ever becomes dynamic."
                ),
            )
        return None

    if list_form and not shell:
        # Structured argument list without shell interpretation: lower risk.
        return None

    origins = [sink.assignments.origin_of(name, sink.call.function_id) for name in info.identifiers]
    worst = worst_origin(origins) if origins else Origin.UNRESOLVED
    if worst is Origin.CONSTANT:
        if shell:
            confidence = adjust_for_partial(Confidence.LOW, sink.partial)
            return EvaluatedSink(
                severity=Severity.INFO,
                confidence=confidence,
                title="Constant command executed with a shell",
                description=(
                    f"Dynamically assembled but constant-valued text reaches "
                    f"`{sink.call.callee_text}` with shell interpretation. No "
                    "untrusted input is visible. Evidence basis: pattern."
                ),
                subject_key=f"{sink.call.callee_text}:constant-shell",
                severity_factors=("constant-valued command text", "shell interpretation"),
                confidence_factors=("origin category: constant", "evidence basis: pattern"),
                impact="Shell interpretation widens impact if the command ever becomes dynamic.",
            )
        return None

    if worst is Origin.EXTERNAL:
        severity = Severity.CRITICAL if shell else Severity.HIGH
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
    shell_phrase = (
        "with shell interpretation"
        if shell
        else ("without explicit shell use" if explicit_no_shell else "as a command string")
    )
    description = (
        f"Potential command injection: user-controlled or unresolved input "
        f"({names}) reaches the command execution sink `{sink.call.callee_text}` "
        f"{shell_phrase} (receiver: {receiver or 'builtin'}). The command text "
        "is built dynamically from the flagged input. Evidence basis: "
        f"{basis}. This pattern deserves security review; it is not a "
        "confirmed vulnerability, and the command was not executed."
    )
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="Potential command injection in dynamically built command",
        description=description,
        subject_key=subject_key(sink.call.callee_text, info.identifiers),
        severity_factors=(
            f"shell interpretation: {'yes' if shell else 'no'}",
            f"origin: {worst.value}",
        ),
        confidence_factors=(f"origin category: {worst.value}", f"evidence basis: {basis}"),
        impact=(
            "If untrusted input can influence the command, an attacker could "
            "execute arbitrary commands with the privileges of the process."
        ),
    )


def execute_command_injection(
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
