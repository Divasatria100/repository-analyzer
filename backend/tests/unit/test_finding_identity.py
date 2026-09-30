"""Finding identity tests (TASK-088): deterministic, reproducible, safe."""

from app.analyzers.findings import compute_identity_key
from tests.fixtures.helpers.analyzer_helpers import make_finding


def test_same_logical_finding_same_id() -> None:
    """Identical logical inputs reproduce the identical key."""
    first = make_finding()
    second = make_finding()
    assert first.identity_key == second.identity_key
    assert len(first.identity_key) == 64  # SHA-256 hex, opaque string


def test_different_rule_location_subject_differ() -> None:
    """Rule, location, and subject changes all rename the finding."""
    base = make_finding()
    assert make_finding(rule_id="SEC-TEST-002").identity_key != base.identity_key
    assert make_finding(path="src/other.py").identity_key != base.identity_key
    assert make_finding(subject_key="other-symbol").identity_key != base.identity_key


def test_identity_independent_of_runtime() -> None:
    """No UUID, execution order, temp path, or object identity in the key."""
    first = make_finding(analysis_id="analysis-1")
    second = make_finding(analysis_id="analysis-1")
    assert first.identity_key == second.identity_key
    key = compute_identity_key(
        analysis_id="a",
        rule_id="SEC-X-1",
        category="security",
        path="f.py",
        start_line=1,
        end_line=1,
        start_column=0,
        end_column=0,
        subject_key="s",
    )
    assert key == compute_identity_key(
        analysis_id="a",
        rule_id="SEC-X-1",
        category="security",
        path="f.py",
        start_line=1,
        end_line=1,
        start_column=0,
        end_column=0,
        subject_key="s",
    )


def test_identity_excludes_volatile_fields() -> None:
    """Severity/config tweaks and reruns never rename a logical finding."""
    base = make_finding()
    from app.analyzers.findings import Confidence, Severity

    assert make_finding(severity=Severity.LOW).identity_key == base.identity_key
    assert make_finding(confidence=Confidence.LOW).identity_key == base.identity_key
