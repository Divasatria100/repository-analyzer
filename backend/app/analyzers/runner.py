"""Isolated analyzer/rule execution (TASK-093).

One rule failure never stops sibling rules; one analyzer failure never
stops other analyzers. Failures are recorded as explicit failure objects
with sanitized messages — a failed rule or analyzer contributes zero
findings but never reads as clean.
"""

from __future__ import annotations

import logging

from app.analyzers.base import Analyzer, AnalyzerFailure, AnalyzerResult, RuleFailure, RuleResult
from app.analyzers.context import AnalysisContext
from app.analyzers.errors import AnalyzerError
from app.analyzers.rules import RegisteredRule, RuleOutcome
from app.core.logging import get_logger, log_event, log_exception, redact_text

_logger = get_logger("analyzers")


def run_rule(analyzer: Analyzer, rule: RegisteredRule, context: AnalysisContext) -> RuleResult:
    """Execute one rule with isolation; failures become records, not silence."""
    from app.analyzers.rules import RuleExecutionContext

    execution_context = RuleExecutionContext(context=context, rule=rule.metadata)
    try:
        outcome: RuleOutcome = rule.execute(execution_context)
    except Exception as exc:
        message = redact_text(f"{type(exc).__name__}: {exc}") if str(exc) else type(exc).__name__
        log_exception(
            _logger,
            "analyzer.rule.failed",
            exc,
            "Rule execution failed",
            analysis_id=context.analysis_id,
            analyzer_id=analyzer.id,
            rule_id=rule.metadata.rule_id,
        )
        return RuleResult(
            rule_id=rule.metadata.rule_id,
            findings=(),
            failure=RuleFailure(
                rule_id=rule.metadata.rule_id,
                analyzer_id=analyzer.id,
                analysis_id=context.analysis_id,
                message=message,
                analyzer_version=analyzer.version,
                rule_set_version=context.rule_set_version,
            ),
            limitations=(),
        )
    log_event(
        _logger,
        logging.INFO,
        "analyzer.rule.completed",
        "Rule execution completed",
        analysis_id=context.analysis_id,
        analyzer_id=analyzer.id,
        rule_id=rule.metadata.rule_id,
        finding_count=len(outcome.findings),
    )
    return RuleResult(
        rule_id=rule.metadata.rule_id,
        findings=tuple(outcome.findings),
        failure=None,
        limitations=tuple(outcome.limitations),
    )


def run_analyzer(analyzer: Analyzer, context: AnalysisContext) -> AnalyzerResult:
    """Execute one analyzer's rules with isolation; analyzer crash is recorded."""
    if analyzer.version != context.analyzer_version:
        log_event(
            _logger,
            logging.WARNING,
            "analyzer.version.mismatch",
            "Analyzer version differs from analysis context",
            analysis_id=context.analysis_id,
            analyzer_id=analyzer.id,
        )
    try:
        rule_results = tuple(analyzer.analyze(context).rule_results)
        findings_count = sum(len(result.findings) for result in rule_results)
    except AnalyzerError as exc:
        log_exception(
            _logger,
            "analyzer.failed",
            exc,
            "Analyzer execution failed",
            analysis_id=context.analysis_id,
            analyzer_id=analyzer.id,
        )
        return AnalyzerResult(
            analyzer_id=analyzer.id,
            analysis_id=context.analysis_id,
            analyzer_version=analyzer.version,
            rule_set_version=context.rule_set_version,
            rule_results=(),
            failure=AnalyzerFailure(
                analyzer_id=analyzer.id,
                analysis_id=context.analysis_id,
                message=exc.user_message,
                analyzer_version=analyzer.version,
                rule_set_version=context.rule_set_version,
            ),
        )
    except Exception as exc:
        log_exception(
            _logger,
            "analyzer.failed",
            exc,
            "Analyzer execution failed",
            analysis_id=context.analysis_id,
            analyzer_id=analyzer.id,
        )
        return AnalyzerResult(
            analyzer_id=analyzer.id,
            analysis_id=context.analysis_id,
            analyzer_version=analyzer.version,
            rule_set_version=context.rule_set_version,
            rule_results=(),
            failure=AnalyzerFailure(
                analyzer_id=analyzer.id,
                analysis_id=context.analysis_id,
                analyzer_version=analyzer.version,
                rule_set_version=context.rule_set_version,
            ),
        )
    log_event(
        _logger,
        logging.INFO,
        "analyzer.completed",
        "Analyzer execution completed",
        analysis_id=context.analysis_id,
        analyzer_id=analyzer.id,
        finding_count=findings_count,
    )
    return AnalyzerResult(
        analyzer_id=analyzer.id,
        analysis_id=context.analysis_id,
        analyzer_version=analyzer.version,
        rule_set_version=context.rule_set_version,
        rule_results=rule_results,
    )
