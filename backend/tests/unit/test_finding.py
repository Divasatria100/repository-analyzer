"""Finding model tests (TASK-086/090): fields, validation, serialization."""

import pytest

from app.analyzers.findings import Confidence, Finding, Limitation, Severity
from tests.fixtures.helpers.analyzer_helpers import make_finding, make_limitation


def test_required_fields_and_valid_location() -> None:
    """A minimal finding carries identity, rule, severity, confidence, location."""
    finding = make_finding()
    assert finding.identity_key
    assert finding.rule_id == "SEC-TEST-001"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.HIGH
    assert finding.location.file_path == "src/app.py"
    assert finding.recommendation == "Review the flagged code."


def test_absolute_location_path_rejected() -> None:
    """Host paths must never enter findings (repository-relative only)."""
    import os

    with pytest.raises(ValueError, match="repository-relative"):
        make_finding(path=os.path.abspath(os.path.join("src", "app.py")))


def test_severity_category_mismatch_rejected() -> None:
    """Architecture findings can never be Critical (frozen vocabulary)."""
    with pytest.raises(ValueError, match="not allowed"):
        make_finding(
            rule_id="ARCH-TEST-001",
            analyzer_id="architecture",
            category="architecture",
            severity=Severity.CRITICAL,
        )


def test_evidence_path_must_match_location() -> None:
    """Evidence that disagrees with the finding location is rejected."""
    from tests.fixtures.helpers.analyzer_helpers import make_evidence

    with pytest.raises(ValueError, match="must match"):
        make_finding(evidence=make_evidence(path="other/file.py"))


def test_recommendation_and_limitation_fields() -> None:
    """Recommendation is advisory text; limitations record what is unknown."""
    finding = make_finding(
        recommendation="Check input validation.",
        limitations=(make_limitation("origin unresolved"),),
    )
    assert finding.recommendation == "Check input validation."
    assert finding.limitations[0].reason == "origin unresolved"


def test_multiple_limitations_and_empty_values() -> None:
    """Multiple limitations preserved in order; empties behave consistently."""
    finding = make_finding(
        limitations=(make_limitation("first"), make_limitation("second", scope="file")),
    )
    assert [limitation.reason for limitation in finding.limitations] == ["first", "second"]
    bare = make_finding(recommendation="", limitations=())
    assert bare.recommendation == ""
    assert bare.limitations == ()
    assert bare.impact is None
    assert bare.finding_id == ""


def test_limitation_validation() -> None:
    """Vacuous limitations fail fast instead of hiding gaps."""
    with pytest.raises(ValueError):
        Limitation(scope="", reason="x")
    with pytest.raises(ValueError):
        Limitation(scope="rule", reason="  ")


def test_serialization_roundtrip() -> None:
    """Findings round-trip deterministically, limitations included."""
    finding = make_finding(
        limitations=(make_limitation("a"), make_limitation("b")),
        severity_factors=("large scope",),
    )
    import json

    first = json.dumps(finding.to_dict(), sort_keys=True)
    rebuilt = Finding.from_dict(finding.to_dict())
    assert rebuilt == finding
    assert json.dumps(rebuilt.to_dict(), sort_keys=True) == first
    assert rebuilt.limitations[1].reason == "b"
    assert rebuilt.severity_factors == ("large scope",)


def test_applied_thresholds_recorded() -> None:
    """Threshold context travels with the finding (effective values, basis)."""
    finding = make_finding(applied_thresholds=(("fan_out", 7),))
    assert finding.applied_thresholds == (("fan_out", 7),)
    assert Finding.from_dict(finding.to_dict()).applied_thresholds == (("fan_out", 7),)
