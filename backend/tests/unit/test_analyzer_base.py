"""Analyzer contract tests (TASK-082): interface, metadata, result shapes."""

import pytest

from app.analyzers.base import Analyzer, AnalyzerResult
from app.analyzers.context import AnalysisContext
from app.analyzers.rules import RegisteredRule, RuleMetadata, RuleOutcome
from tests.fixtures.helpers.analyzer_helpers import make_context, make_rule


class StubAnalyzer(Analyzer):
    """Minimal concrete analyzer (test infrastructure, not a real capability)."""

    id = "stub"
    name = "Stub Analyzer"
    version = "0.1.0"

    def rules(self) -> list[RegisteredRule]:
        """No rules: exercises the empty-analyzer path."""
        return []


def test_valid_analyzer_implementation() -> None:
    """A concrete analyzer exposes identity and runs against context."""
    analyzer = StubAnalyzer()
    assert analyzer.id == "stub"
    assert analyzer.name == "Stub Analyzer"
    assert analyzer.version == "0.1.0"
    result = analyzer.analyze(make_context())
    assert isinstance(result, AnalyzerResult)
    assert result.analyzer_id == "stub"
    assert result.failed is False
    assert result.findings == ()


def test_abstract_analyzer_cannot_instantiate() -> None:
    """The contract requires rules() and analyze() implementations."""
    with pytest.raises(TypeError):
        Analyzer()  # type: ignore[abstract]


def test_required_metadata_present() -> None:
    """Identity fields exist on every analyzer (used in logs and results)."""
    assert StubAnalyzer.id and StubAnalyzer.name and StubAnalyzer.version


def test_context_passing() -> None:
    """Rules receive the exact context object through the real execution path."""
    seen: list[AnalysisContext] = []

    def execute(execution_context) -> RuleOutcome:  # type: ignore[no-untyped-def]
        seen.append(execution_context.context)
        return RuleOutcome()

    class ObservingAnalyzer(StubAnalyzer):
        id = "observer"

        def rules(self) -> list[RegisteredRule]:
            return [RegisteredRule(metadata=make_rule(), execute=execute)]

    context = make_context(analysis_id="analysis-9")
    ObservingAnalyzer().analyze(context)
    assert seen == [context]
    assert seen[0].analysis_id == "analysis-9"


def test_invalid_analyzer_contract() -> None:
    """Missing rules() implementation fails fast at instantiation."""

    class BrokenAnalyzer(Analyzer):
        id = "broken"
        name = "Broken"
        version = "0.1.0"

    with pytest.raises(TypeError):
        BrokenAnalyzer()  # type: ignore[abstract]


def test_rule_metadata_validation() -> None:
    """RuleMetadata rejects malformed declarations (fail fast, never silent)."""
    with pytest.raises(ValueError):
        make_rule(rule_id="no-prefix-here")
    with pytest.raises(ValueError):
        RuleMetadata(
            rule_id="SEC-TEST-002",
            name="",
            description="x",
            analyzer_id="security",
            version="1.0",
            default_severity="High",
        )
