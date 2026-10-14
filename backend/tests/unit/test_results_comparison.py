"""Snapshot comparison unit tests (Phase 11, TASK-160).

Identity-only matching, qualifications, comparability guards, and the
canonical comparison serialization. Pure layer, no database.
"""

from app.results.canonical import comparison_to_dict
from app.results.comparison import (
    SnapshotView,
    compare_snapshots,
)


def _view(
    analysis_id: str,
    findings: tuple[tuple[str, str, str, str], ...] = (),
    domain_states: tuple[tuple[str, str | None], ...] = (
        ("security", None),
        ("architecture", None),
        ("dependency", None),
        ("code_structure", None),
    ),
    rule_states: tuple[tuple[str, str, str], ...] = (),
    commit_sha: str | None = "c" * 40,
    analyzer_version: str = "1.0.0",
    rule_set_version: str = "1.0.0",
) -> SnapshotView:
    return SnapshotView(
        analysis_id=analysis_id,
        repository_id="r" * 32,
        commit_sha=commit_sha,
        timestamp="2026-10-14T00:00:00Z",
        analyzer_version=analyzer_version,
        rule_set_version=rule_set_version,
        configuration={"generated_files": "Included"},
        advisory_source="OSV",
        advisory_status="succeeded",
        findings=findings,
        domain_states=domain_states,
        rule_states=rule_states,
    )


def test_classifies_new_resolved_unchanged_by_identity() -> None:
    base = _view(
        "a" * 32,
        findings=(
            ("keep", "SEC-A", "security", "F-0001"),
            ("gone", "SEC-B", "security", "F-0002"),
        ),
    )
    target = _view(
        "b" * 32,
        findings=(
            ("keep", "SEC-A", "security", "F-0099"),
            ("fresh", "SEC-C", "security", "F-0100"),
        ),
    )
    result = compare_snapshots(base, target)
    assert result.comparable
    # Same identity with different finding ids is Unchanged, never New.
    assert [entry.identity_key for entry in result.unchanged] == ["keep"]
    assert result.unchanged[0].base_finding_id == "F-0001"
    assert result.unchanged[0].target_finding_id == "F-0099"
    assert [entry.identity_key for entry in result.resolved] == ["gone"]
    assert [entry.identity_key for entry in result.new] == ["fresh"]


def test_not_comparable_guards() -> None:
    base = _view("a" * 32)
    other_repo = SnapshotView(
        analysis_id="b" * 32,
        repository_id="q" * 32,
        commit_sha="c" * 40,
        timestamp=None,
        analyzer_version="1.0.0",
        rule_set_version="1.0.0",
        configuration={},
        advisory_source=None,
        advisory_status=None,
    )
    assert not compare_snapshots(base, other_repo).comparable
    assert not compare_snapshots(base, base).comparable


def test_context_differences_recorded() -> None:
    base = _view("a" * 32)
    target = _view("b" * 32, analyzer_version="2.0.0")
    result = compare_snapshots(base, target)
    assert result.context_differences["analyzer_version"]
    assert not result.context_differences["rule_set_version"]
    assert result.base_context["analyzer_version"] == "1.0.0"
    assert result.target_context["analyzer_version"] == "2.0.0"


def test_incomplete_target_scope_qualifies_resolved() -> None:
    base = _view("a" * 32, findings=(("gone", "ARCH-X", "architecture", "F-0001"),))
    target = _view(
        "b" * 32,
        domain_states=(
            ("security", None),
            ("architecture", "Analysis incomplete"),
            ("dependency", None),
            ("code_structure", None),
        ),
        rule_states=(("architecture", "ARCH-X", "Not evaluated"),),
    )
    result = compare_snapshots(base, target)
    assert len(result.qualifications) == 2
    assert result.resolved[0].qualified
    payload = comparison_to_dict(result)
    assert payload["comparable"]
    assert payload["resolved"][0]["qualified"]
    assert payload["resolved"][0]["base_finding_id"] == "F-0001"


def test_not_comparable_serialization() -> None:
    result = compare_snapshots(_view("a" * 32), _view("a" * 32))
    assert comparison_to_dict(result) == {
        "comparable": False,
        "reason": "Baseline and target are the same analysis.",
    }
