"""Severity/confidence tests (TASK-087): frozen vocabularies, independence."""

from app.analyzers.findings import Confidence, Severity
from tests.fixtures.helpers.analyzer_helpers import make_finding


def test_severity_vocabulary() -> None:
    """Security uses exactly Critical/High/Medium/Low/Info (SEC-REQ-017)."""
    assert [level.value for level in Severity] == ["Critical", "High", "Medium", "Low", "Info"]


def test_architecture_subset_excludes_critical() -> None:
    """Architecture uses High/Medium/Low/Info, never Critical (ARCH-REQ-077)."""
    assert Severity.allowed_for("architecture") == {
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    }
    for category in ("security", "dependency", "code_structure"):
        assert Severity.allowed_for(category) == frozenset(Severity)


def test_confidence_vocabulary() -> None:
    """Confidence uses exactly High/Medium/Low (SEC-REQ-020)."""
    assert [level.value for level in Confidence] == ["High", "Medium", "Low"]


def test_severity_confidence_independent() -> None:
    """High severity with Low confidence is valid; neither implies the other."""
    finding = make_finding(severity=Severity.HIGH, confidence=Confidence.LOW)
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.LOW
    finding = make_finding(severity=Severity.INFO, confidence=Confidence.HIGH)
    assert finding.severity == Severity.INFO
    assert finding.confidence == Confidence.HIGH


def test_no_numeric_scores_exist() -> None:
    """No security/quality/risk/confidence scores anywhere in the model."""
    finding = make_finding()
    fields = set(finding.to_dict())
    for forbidden in ("score", "security_score", "quality_score", "risk_score", "confidence_score"):
        assert forbidden not in fields, forbidden
    assert not hasattr(finding, "security_score")
    assert not hasattr(finding, "risk_score")
