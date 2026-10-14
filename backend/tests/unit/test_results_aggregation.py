"""Result aggregation unit tests (Phase 11, TASK-146/147).

Pure layer: domain states, rule evaluations, file coverages, outcomes,
configuration snapshots. No database, no network, no analyzer execution.
"""

import pytest

from app.analyzers.findings import Confidence, Severity, create_finding
from app.ncm import SourceLocation
from app.results.aggregation import (
    AREAS,
    AdvisoryInfo,
    AnalysisMeta,
    DomainInput,
    FileMeta,
    RuleCoverage,
    aggregate,
    default_configuration,
    derive_domain_state,
    derive_file_coverages,
    derive_outcome,
    normalize_coverage_status,
)


def _finding(
    rule_id: str = "SEC-HARDCODED-SECRET",
    category: str = "security",
    path: str = "app/main.py",
    identity: str = "id-1",
) -> object:
    return create_finding(
        rule_id=rule_id,
        analyzer_id=category,
        category=category,
        title="title",
        description="description",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=SourceLocation(path, 1, 1, 0, 0),
        recommendation="fix",
        analysis_id="a" * 32,
        subject_key=f"subject:{identity}",
        identity_key=identity,
    )


def _bundle(category: str = "security", **overrides: object) -> DomainInput:
    values: dict[str, object] = {
        "analyzer_id": category,
        "category": category,
        "findings": (),
        "rule_failures": (),
        "analyzer_failed": False,
        "coverages": (RuleCoverage("SEC-RULE", "covered"),),
        "limitations": (),
        "limited": False,
    }
    values.update(overrides)
    return DomainInput(**values)  # type: ignore[arg-type]


def test_domain_state_precedence() -> None:
    assert derive_domain_state(_bundle(analyzer_failed=True)).state == "Analysis failed"
    failed = _bundle(coverages=(RuleCoverage("R1", "failed"),))
    assert derive_domain_state(failed).state == "Analysis failed"
    incomplete = _bundle(rule_failures=("R1",))
    assert derive_domain_state(incomplete).state == "Analysis incomplete"
    assert "R1" in (incomplete_reason := derive_domain_state(incomplete).reason or "")
    assert incomplete_reason
    partial = _bundle(coverages=(RuleCoverage("R1", "partial"),))
    assert derive_domain_state(partial).state == "Analysis incomplete"
    assert derive_domain_state(_bundle(coverages=())).state == "Analysis not performed"
    skipped = _bundle(coverages=(RuleCoverage("R1", "unsupported"),))
    assert derive_domain_state(skipped).state == "Analysis not performed"


def test_domain_state_clean_cases() -> None:
    with_findings = _bundle(findings=(_finding(),))  # type: ignore[arg-type]
    clean = derive_domain_state(with_findings)
    assert clean.state is None and clean.reason is None
    empty = derive_domain_state(_bundle())
    assert empty.state == "No findings detected" and empty.reason is None


def test_normalize_coverage_status() -> None:
    assert normalize_coverage_status("covered") == "Evaluated"
    assert normalize_coverage_status("partial") == "Partially evaluated"
    assert normalize_coverage_status("unsupported") == "Not evaluated"
    assert normalize_coverage_status("failed") == "Failed"
    with pytest.raises(ValueError):
        normalize_coverage_status("mystery")


def test_file_coverages_source_areas() -> None:
    files = [
        FileMeta(path="app/main.py", language="python", parse_result="parsed"),
        FileMeta(path="app/broken.py", language="python", parse_result="failed"),
        FileMeta(path="app/warn.py", language="python", parse_result="parsed_with_diagnostics"),
        FileMeta(path="web/app.js", language="javascript"),
        FileMeta(path="requirements.txt", file_type="manifest"),
        FileMeta(path="README.md"),
    ]
    records = derive_file_coverages(files, {"requirements.txt": "Fully analyzed"})
    by_key = {(item.path, item.scope_value): item.state for item in records}
    assert ("app/broken.py", "security") in by_key
    assert by_key[("app/broken.py", "security")] == "Failed"
    assert by_key[("app/warn.py", "architecture")] == "Partially analyzed"
    assert by_key[("web/app.js", "security")] == "Not analyzed"
    # Fully analyzed rows are sparse: parsed python vanishes for source
    # areas (but stays Not analyzed for dependency, which only reads
    # manifests), and covered manifests vanish entirely.
    assert not any(
        item.path == "app/main.py" and item.scope_value != "dependency" for item in records
    )
    assert by_key[("app/main.py", "dependency")] == "Not analyzed"
    # Manifests vanish for dependency but stay Not analyzed for source areas.
    assert not any(
        item.path == "requirements.txt" and item.scope_value == "dependency" for item in records
    )
    assert by_key[("requirements.txt", "security")] == "Not analyzed"
    assert by_key[("README.md", "dependency")] == "Not analyzed"


def test_aggregate_dedupes_and_records_collision() -> None:
    first = _finding(identity="same")
    second = _finding(identity="same", path="app/other.py")
    meta = AnalysisMeta(analysis_id="a" * 32, repository_id="r" * 32)
    result = aggregate(meta, [], [_bundle(findings=(first, second))])  # type: ignore[arg-type]
    assert len(result.findings) == 1
    assert any("Duplicate identity" in item.reason for item in result.limitations)
    assert result.outcome == "Completed with limitations"


def test_aggregate_outcome_completed_only_when_fully_clean() -> None:
    meta = AnalysisMeta(analysis_id="a" * 32, repository_id="r" * 32)
    clean = aggregate(
        meta,
        [],
        [_bundle(category=area, coverages=()) for area in AREAS],
        registered_rules={area: () for area in AREAS},
    )
    # No coverages at all means Not performed domains: never Completed.
    assert clean.outcome == "Completed with limitations"
    outcome, _ = derive_outcome([], [], [])
    assert outcome == "Failed"


def test_default_configuration_shape() -> None:
    configuration = default_configuration({"fan_out": 5, "coupling": 7})
    assert configuration["generated_files"] == "Included"
    architecture = configuration["architecture"]
    assert isinstance(architecture, dict)
    assert architecture["coupling_definition"] == "coupling-def-1"
    assert architecture["thresholds"]["ARCH-HIGH-FAN-OUT"] == {"fan_out": 5}
    assert configuration["thresholds"] == {"coupling": 7, "fan_out": 5}


def test_advisory_info_defaults_unavailable() -> None:
    assert AdvisoryInfo(source="OSV").status == "Unavailable"


def test_duplicate_domain_categories_rejected() -> None:
    meta = AnalysisMeta(analysis_id="a" * 32, repository_id="r" * 32)
    with pytest.raises(ValueError, match="Duplicate domain inputs"):
        aggregate(meta, [], [_bundle(), _bundle()])
