"""Failure isolation tests (TASK-093): failures recorded, never clean."""

from app.analyzers.base import Analyzer, AnalyzerResult
from app.analyzers.errors import AnalyzerError, RuleFailedError
from app.analyzers.rules import (
    RegisteredRule,
    RuleOutcome,
)
from app.analyzers.runner import run_analyzer, run_rule
from tests.fixtures.helpers.analyzer_helpers import make_context, make_finding, make_rule


def _ok_executor(tag: str):  # type: ignore[no-untyped-def]
    def execute(execution_context) -> RuleOutcome:  # type: ignore[no-untyped-def]
        return RuleOutcome(
            findings=[
                make_finding(
                    rule_id=execution_context.rule.rule_id,
                    subject_key=tag,
                    analysis_id=execution_context.context.analysis_id,
                )
            ]
        )

    return execute


def _boom_executor(execution_context) -> RuleOutcome:  # type: ignore[no-untyped-def]
    raise RuntimeError("boom")


class TrioAnalyzer(Analyzer):
    """Test analyzer: ok / failing / ok (test infrastructure only)."""

    id = "trio"
    name = "Trio"
    version = "0.1.0"

    def rules(self) -> list[RegisteredRule]:
        """Two passing rules around one crashing rule."""
        return [
            RegisteredRule(metadata=make_rule("SEC-TEST-001"), execute=_ok_executor("a")),
            RegisteredRule(metadata=make_rule("SEC-TEST-002"), execute=_boom_executor),
            RegisteredRule(metadata=make_rule("SEC-TEST-003"), execute=_ok_executor("c")),
        ]


class ExplodingAnalyzer(Analyzer):
    """Test analyzer whose rule listing itself raises (test infrastructure only)."""

    id = "exploding"
    name = "Exploding"
    version = "0.1.0"

    def rules(self) -> list[RegisteredRule]:
        """Unreachable rule set: listing raises before any rule runs."""
        raise RuntimeError("analyzer boom")


def test_rule_failure_preserves_siblings() -> None:
    """A finds remain, B failure recorded, C still executes."""
    result = TrioAnalyzer().analyze(make_context())
    assert isinstance(result, AnalyzerResult)
    assert result.failed is False
    assert [finding.rule_id for finding in result.findings] == ["SEC-TEST-001", "SEC-TEST-003"]
    by_rule = {rr.rule_id: rr for rr in result.rule_results}
    assert by_rule["SEC-TEST-002"].failure is not None
    assert by_rule["SEC-TEST-002"].failure.rule_id == "SEC-TEST-002"
    assert by_rule["SEC-TEST-002"].findings == ()
    assert by_rule["SEC-TEST-001"].failure is None


def test_failed_rule_is_not_clean() -> None:
    """A failed rule carries a failure record — never an empty clean result."""
    result = TrioAnalyzer().analyze(make_context())
    failed = [rr for rr in result.rule_results if rr.failure is not None]
    assert len(failed) == 1
    assert failed[0].failure.message
    assert failed[0].failure.category == "analyzer failure"


def test_analyzer_failure_preserves_siblings() -> None:
    """Analyzer A fails, analyzer B still executes fully."""
    bad = run_analyzer(ExplodingAnalyzer(), make_context())
    assert bad.failed is True
    assert bad.findings == ()
    assert bad.failure is not None
    assert bad.failure.analyzer_id == "exploding"
    good = run_analyzer(TrioAnalyzer(), make_context())
    assert good.failed is False
    assert len(good.findings) == 2


def test_failed_analyzer_is_not_clean() -> None:
    """A failed analyzer carries failure state, not an empty finding list."""
    result = run_analyzer(ExplodingAnalyzer(), make_context())
    assert result.failed is True
    assert result.failure is not None
    assert result.failure.category == "analyzer failure"
    assert result.rule_results == ()


def test_rule_failed_error_carries_rule_id() -> None:
    """RuleFailedError binds the failing rule for structured reporting."""
    error = RuleFailedError("SEC-TEST-007")
    assert error.rule_id == "SEC-TEST-007"
    assert isinstance(error, AnalyzerError)


def test_run_rule_records_sanitized_failure() -> None:
    """Direct run_rule converts crashes to records without internals."""
    from app.analyzers.base import Analyzer as BaseAnalyzer

    class Single(BaseAnalyzer):
        id = "single"
        name = "Single"
        version = "0.1.0"

        def rules(self) -> list[RegisteredRule]:
            return [RegisteredRule(metadata=make_rule("SEC-TEST-009"), execute=_boom_executor)]

    analyzer = Single()
    outcome = run_rule(analyzer, analyzer.rules()[0], make_context())
    assert outcome.failure is not None
    assert outcome.findings == ()
    assert "boom" in outcome.failure.message
    assert outcome.failure.analyzer_version == "0.1.0"
    assert outcome.failure.rule_set_version == "1.0"
