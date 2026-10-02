"""Security analyzer execution pipeline (TASK-094, extended Phase 8).

The ``security`` analyzer runs the nine registered V1.0 rules
through the existing Phase 6 machinery:

* identity via :class:`app.analyzers.base.Analyzer` (``id = "security"``),
* rule discovery via :class:`app.analyzers.rules.RuleRegistry`
  (deterministic rule-ID order; no hard-coded rule chain),
* per-rule failure isolation via :func:`app.analyzers.runner.run_rule`
  (inherited from the final ``Analyzer.analyze``),
* deterministic output (sorted findings, identity-key dedup),
* findings through the common Finding model only.

The analyzer consumes :class:`AnalysisContext` (NCM + versions) plus a
narrow :class:`SourceProvider` for bounded read-as-data excerpts around
NCM-located sinks. It never imports parsers, never executes repository
code, and never performs network access. It runs only security rules.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from app.analyzers.base import Analyzer
from app.analyzers.rules import RegisteredRule, RuleExecutionContext, RuleOutcome
from app.analyzers.security.coverage import Coverage, CoverageStatus, coverage_for, summarize_scope
from app.analyzers.security.metadata import (
    SECURITY_ANALYZER_ID,
    SECURITY_RULE_SPECS,
    SecurityRuleSpec,
)
from app.analyzers.security.rules import (
    command_injection,
    cors,
    crypto,
    deserialization,
    dynamic_execution,
    path_traversal,
    sql_injection,
    ssrf,
    tls,
)
from app.analyzers.security.source import SourceProvider
from app.analyzers.versioning import RULE_SET_VERSION
from app.core.logging import get_logger, log_event
from app.ncm import NcmRepository

_logger = get_logger("analyzers.security")

#: Analyzer version for V1.0 (follows the application-version convention;
#: kept as a constant so repeated analyses are deterministic).
SECURITY_ANALYZER_VERSION = "0.1.0"


def _bind(
    spec: SecurityRuleSpec,
    source: SourceProvider | None,
    runner: Callable[
        [RuleExecutionContext, SourceProvider | None],
        tuple[RuleOutcome, Coverage],
    ],
) -> RegisteredRule:
    """Bind a rule implementation to its metadata and source access."""

    def execute(execution_context: RuleExecutionContext) -> RuleOutcome:
        outcome, _ = runner(execution_context, source)
        return outcome

    return RegisteredRule(metadata=spec.to_metadata(RULE_SET_VERSION), execute=execute)


_RULE_RUNNERS = (
    sql_injection.execute_sql_injection,
    command_injection.execute_command_injection,
    path_traversal.execute_path_traversal,
    ssrf.execute_ssrf,
    deserialization.execute_unsafe_deserialization,
    dynamic_execution.execute_dangerous_dynamic_execution,
    crypto.execute_weak_crypto,
    tls.execute_disabled_tls,
    cors.execute_insecure_cors,
)


def build_security_rules(source: SourceProvider | None) -> list[RegisteredRule]:
    """Build the registered security rules (deterministic rule-ID order)."""
    bound = [
        _bind(spec, source, runner)
        for spec, runner in zip(SECURITY_RULE_SPECS, _RULE_RUNNERS, strict=True)
    ]
    return sorted(bound, key=lambda rule: rule.metadata.rule_id)


class SecurityAnalyzer(Analyzer):
    """Static injection-finding analyzer over NCM plus bounded source data."""

    id = SECURITY_ANALYZER_ID
    name = "Security Analyzer"
    version = SECURITY_ANALYZER_VERSION

    def __init__(self, source: SourceProvider | None = None) -> None:
        self._source = source

    def rules(self) -> list[RegisteredRule]:
        """Only the registered V1.0 security rules (never other domains)."""
        return build_security_rules(self._source)

    def coverage(self, ncm: NcmRepository) -> list[Coverage]:
        """Explicit per-rule coverage for an NCM snapshot (never "secure")."""
        scope = summarize_scope(ncm)
        coverages: list[Coverage] = []
        for spec in SECURITY_RULE_SPECS:
            if not scope.has_supported_content:
                coverages.append(
                    Coverage(
                        rule_id=spec.rule_id,
                        status=CoverageStatus.UNSUPPORTED,
                        reason="No supported-language (python) content in scope.",
                    )
                )
                continue
            sinks_found = _sinks_present(ncm, spec)
            coverages.append(coverage_for(spec.rule_id, scope, sinks_found=sinks_found))
        log_event(
            _logger,
            logging.INFO,
            "security.coverage.computed",
            "Security coverage computed",
            coverage={item.rule_id: item.status.value for item in coverages},
        )
        return coverages


def _sinks_present(ncm: NcmRepository, spec: SecurityRuleSpec) -> bool:
    """True when any supported-language call site matches the rule's sinks."""
    from app.analyzers.security.sinks import (
        COMMAND_SINKS,
        CORS_MIDDLEWARE_SINKS,
        CRYPTO_SINKS,
        DESERIALIZATION_SINKS,
        DYNAMIC_EXEC_SINKS,
        PATH_SINKS,
        RANDOM_SINKS,
        SSRF_SINKS,
        TLS_CALL_SINKS,
        callee_matches,
        sql_sink_match,
    )

    for entry in ncm.files:
        module = entry.module
        if module is None or (module.language or "").lower() != "python":
            continue
        import_targets = frozenset(imp.target_text for imp in module.imports)
        for call in module.calls:
            callee = call.callee_text
            if spec.rule_id == "SEC-SQL-INJECTION":
                if sql_sink_match(callee, import_targets):
                    return True
            elif spec.rule_id == "SEC-COMMAND-INJECTION":
                if callee_matches(callee, COMMAND_SINKS, import_targets):
                    return True
            elif spec.rule_id == "SEC-PATH-TRAVERSAL":
                if callee_matches(callee, PATH_SINKS, import_targets):
                    return True
            elif spec.rule_id == "SEC-SSRF":
                if callee_matches(callee, SSRF_SINKS, import_targets):
                    return True
            elif spec.rule_id == "SEC-UNSAFE-DESERIALIZATION":
                if callee_matches(callee, DESERIALIZATION_SINKS, import_targets):
                    return True
            elif spec.rule_id == "SEC-DANGEROUS-DYNAMIC-EXECUTION":
                if callee_matches(callee, DYNAMIC_EXEC_SINKS, import_targets):
                    return True
            elif spec.rule_id == "SEC-WEAK-CRYPTO":
                if callee_matches(callee, CRYPTO_SINKS, import_targets):
                    return True
                if callee_matches(callee, RANDOM_SINKS, import_targets):
                    return True
            elif spec.rule_id == "SEC-DISABLED-TLS":
                if callee_matches(callee, TLS_CALL_SINKS, import_targets):
                    return True
            elif spec.rule_id == "SEC-INSECURE-CORS":
                if callee_matches(callee, CORS_MIDDLEWARE_SINKS, import_targets):
                    return True
    return False
