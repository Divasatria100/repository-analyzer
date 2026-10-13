"""Duplicate-version and high-count detection tests (TASK-116/117).

Duplicate comparison uses resolved exact versions only; the count rule uses
the frozen ``dependencies`` threshold with strict ``>`` per ecosystem scope
(frozen DEP-REQ-003 occurrence semantics: total occurrences, PyPI and npm
separately).
"""

from tests.fixtures.helpers.dependency_helpers import analyze_manifests, rule_result


def test_same_package_same_version_is_not_duplicate() -> None:
    result, _, _ = analyze_manifests(
        {
            "requirements.txt": "requests==2.31.0\n",
            "services/api/requirements.txt": "requests==2.31.0\n",
        }
    )
    assert rule_result(result, "DEP-DUPLICATE-VERSION").findings == ()


def test_same_package_two_exact_versions_is_finding() -> None:
    result, _, _ = analyze_manifests(
        {
            "requirements.txt": "requests==2.31.0\n",
            "services/api/requirements.txt": "requests==2.28.0\n",
        }
    )
    findings = rule_result(result, "DEP-DUPLICATE-VERSION").findings
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity.value == "Low"
    assert finding.confidence.value == "High"
    assert "2.28.0" in finding.description and "2.31.0" in finding.description


def test_constraints_without_resolved_versions_are_not_duplicates() -> None:
    result, _, _ = analyze_manifests({"requirements.txt": "flask>=2.0\nflask<4.0\n"})
    assert rule_result(result, "DEP-DUPLICATE-VERSION").findings == ()
    limitations = rule_result(result, "DEP-DUPLICATE-VERSION").limitations
    assert any("unknown versions" in item.reason for item in limitations)


def test_different_packages_never_duplicates() -> None:
    result, _, _ = analyze_manifests({"requirements.txt": "flask==3.0.0\nrequests==3.0.0\n"})
    assert rule_result(result, "DEP-DUPLICATE-VERSION").findings == ()


def test_duplicate_evidence_lists_versions_and_occurrences() -> None:
    result, _, _ = analyze_manifests(
        {
            "requirements.txt": "Django==4.2.0\n",
            "services/api/requirements.txt": "Django==3.2.0\n",
        }
    )
    (finding,) = rule_result(result, "DEP-DUPLICATE-VERSION").findings
    assert "django" in finding.title
    assert "requirements.txt" in finding.description
    assert "services/api/requirements.txt" in finding.description


def test_count_exactly_200_is_not_finding() -> None:
    manifests = {
        "requirements.txt": "".join(f"pkg{i}==1.0.0\n" for i in range(200)),
    }
    result, _, _ = analyze_manifests(manifests)
    assert rule_result(result, "DEP-HIGH-DEPENDENCY-COUNT").findings == ()


def test_count_201_is_finding() -> None:
    manifests = {
        "requirements.txt": "".join(f"pkg{i}==1.0.0\n" for i in range(201)),
    }
    result, _, _ = analyze_manifests(manifests)
    (finding,) = rule_result(result, "DEP-HIGH-DEPENDENCY-COUNT").findings
    assert finding.severity.value == "Low"
    assert finding.confidence.value == "High"
    assert "201" in finding.description
    assert finding.applied_thresholds == (("dependencies", 200),)
    assert "not a vulnerability" in finding.description


def test_count_scopes_are_separate() -> None:
    manifests = {
        "requirements.txt": "".join(f"pkg{i}==1.0.0\n" for i in range(150)),
        "package.json": (
            '{"dependencies": {' + ",".join(f'"npm{i}": "1.0.0"' for i in range(150)) + "}}"
        ),
    }
    result, _, _ = analyze_manifests(manifests)
    assert rule_result(result, "DEP-HIGH-DEPENDENCY-COUNT").findings == ()


def test_repeated_occurrences_count_but_unique_identity_rule() -> None:
    """Occurrence semantics: duplicates inflate the count (frozen DEP-REQ-003)."""
    manifests = {
        "requirements.txt": "".join("requests==2.31.0\n" for _ in range(201)),
    }
    result, _, _ = analyze_manifests(manifests)
    assert len(rule_result(result, "DEP-HIGH-DEPENDENCY-COUNT").findings) == 1
    # ...but identical versions are not duplicate-version findings.
    assert rule_result(result, "DEP-DUPLICATE-VERSION").findings == ()


def test_threshold_uses_centralized_strict_exceed() -> None:
    from app.analyzers.thresholds import default_thresholds

    assert default_thresholds().dependencies == 200
    assert default_thresholds().exceeds("dependencies", 200) is False
    assert default_thresholds().exceeds("dependencies", 201) is True


def _v2_dual_lockfile(count: int) -> str:
    """A valid v2 lockfile with both `packages` and legacy `dependencies`."""
    packages = ",".join(f'"node_modules/pkg{i}": {{"version": "1.0.0"}}' for i in range(count))
    legacy = ",".join(f'"pkg{i}": {{"version": "1.0.0"}}' for i in range(count))
    return (
        '{"lockfileVersion": 2, "packages": {"": {"name": "demo"},'
        f"{packages}" + '}, "dependencies": {' + f"{legacy}" + "}}"
    )


def test_v2_dual_representation_counts_each_package_once() -> None:
    """FAIL-1: 200 real packages in both sections still count as 200."""
    from app.analyzers.dependency.analyzer import DictManifestProvider, build_inventory

    inventory = build_inventory(DictManifestProvider({"package-lock.json": _v2_dual_lockfile(200)}))
    assert len(inventory.occurrences) == 200
    result, _, _ = analyze_manifests({"package-lock.json": _v2_dual_lockfile(200)})
    assert rule_result(result, "DEP-HIGH-DEPENDENCY-COUNT").findings == ()


def test_v2_true_201_fires_threshold() -> None:
    """FAIL-1: the threshold fires on 201 genuinely distinct occurrences."""
    result, _, _ = analyze_manifests({"package-lock.json": _v2_dual_lockfile(201)})
    (finding,) = rule_result(result, "DEP-HIGH-DEPENDENCY-COUNT").findings
    assert "201" in finding.description


def test_v2_distinct_transitives_and_versions_survive_dedup() -> None:
    """FAIL-1/C3: dedup removes representations, never real nodes/versions."""
    from app.analyzers.dependency.analyzer import DictManifestProvider, build_inventory

    text = """\
{
  "lockfileVersion": 2,
  "packages": {
    "": {"name": "demo", "dependencies": {"a": "^1.0.0"}},
    "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2.0.0"}},
    "node_modules/b": {"version": "2.0.0"},
    "node_modules/c/node_modules/b": {"version": "2.1.0"}
  },
  "dependencies": {
    "a": {"version": "1.0.0", "requires": {"b": "^2.0.0"}},
    "b": {"version": "2.0.0"}
  }
}
"""
    inventory = build_inventory(DictManifestProvider({"package-lock.json": text}))
    by_name: dict[str, list[str | None]] = {}
    for occ in inventory.occurrences:
        by_name.setdefault(occ.original_name, []).append(occ.resolved_version)
    assert sorted(by_name["b"]) == ["2.0.0", "2.1.0"]  # both real versions kept
    assert by_name["a"] == ["1.0.0"]  # counted once despite two representations
