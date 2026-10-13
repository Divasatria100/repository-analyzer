"""Dependency finding/result normalization tests (TASK-121).

Findings use the common Finding model with frozen severities/confidences,
deterministic identities, redacted evidence, and explicit limitations.
Inventory, diagnostics, coverage, and advisory findings stay distinct.
"""

from app.analyzers.dependency.analyzer import DependencyAnalyzer, DictManifestProvider
from app.analyzers.dependency.metadata import DEPENDENCY_RULE_SPECS
from tests.fixtures.helpers.analyzer_helpers import make_context
from tests.fixtures.helpers.dependency_helpers import analyze_manifests, rule_result
from tests.fixtures.helpers.security_helpers import parse_files


def test_four_rules_registered_in_order() -> None:
    analyzer = DependencyAnalyzer(DictManifestProvider({}))
    assert [rule.metadata.rule_id for rule in analyzer.rules()] == [
        "DEP-DUPLICATE-VERSION",
        "DEP-HIGH-DEPENDENCY-COUNT",
        "DEP-KNOWN-VULNERABILITY",
        "DEP-UNUSED-CANDIDATE",
    ]
    assert all(rule.metadata.analyzer_id == "dependency" for rule in analyzer.rules())


def test_rule_metadata_matches_frozen_assignments() -> None:
    by_id = {spec.rule_id: spec for spec in DEPENDENCY_RULE_SPECS}
    assert by_id["DEP-KNOWN-VULNERABILITY"].default_severity == "High"
    assert by_id["DEP-DUPLICATE-VERSION"].default_severity == "Low"
    assert by_id["DEP-HIGH-DEPENDENCY-COUNT"].default_severity == "Low"
    assert by_id["DEP-UNUSED-CANDIDATE"].default_severity == "Info"
    assert by_id["DEP-UNUSED-CANDIDATE"].default_confidence == "Low"


def test_finding_identities_are_deterministic() -> None:
    manifests = {
        "requirements.txt": "requests==2.31.0\n",
        "services/api/requirements.txt": "requests==2.28.0\n",
    }
    first, _, _ = analyze_manifests(manifests)
    second, _, _ = analyze_manifests(manifests)
    first_ids = sorted(item.identity_key for item in first.findings)
    second_ids = sorted(item.identity_key for item in second.findings)
    assert first_ids and first_ids == second_ids
    for finding in first.findings:
        rebuilt = analyze_manifests(manifests)[0]
        assert finding.identity_key in {item.identity_key for item in rebuilt.findings}


def test_finding_identity_excludes_timestamps() -> None:
    manifests = {"requirements.txt": "requests==2.31.0\n"}
    first, _, _ = analyze_manifests(manifests)
    second, _, _ = analyze_manifests(manifests, analysis_id="analysis-1")
    assert {item.identity_key for item in first.findings} == {
        item.identity_key for item in second.findings
    }


def test_evidence_redacts_credentials() -> None:
    manifests = {
        "requirements.txt": "pkg @ https://user:secret-value-123@example.test/pkg.zip\n",
    }
    result, _, _ = analyze_manifests(manifests)
    for finding in result.findings:
        for line in finding.evidence.lines if finding.evidence else ():
            assert "secret-value-123" not in line
        assert "secret-value-123" not in finding.description


def test_inventory_is_not_a_vulnerability() -> None:
    result, context, analyzer = analyze_manifests({"requirements.txt": "requests==2.31.0\n"})
    inventory = analyzer.inventory_for(context)
    assert len(inventory.occurrences) == 1
    categories = {finding.category for finding in result.findings}
    assert categories <= {"dependency"}
    assert rule_result(result, "DEP-KNOWN-VULNERABILITY").findings == ()


def test_malformed_manifest_produces_limitation_not_clean() -> None:
    result, _, _ = analyze_manifests({"package.json": "{oops"})
    for rule_id in (
        "DEP-KNOWN-VULNERABILITY",
        "DEP-DUPLICATE-VERSION",
        "DEP-HIGH-DEPENDENCY-COUNT",
        "DEP-UNUSED-CANDIDATE",
    ):
        limitations = rule_result(result, rule_id).limitations
        assert any(
            "package.json" in item.reason or "package.json" in (item.path or "")
            for item in limitations
        )


def test_coverage_is_explicit() -> None:
    _, context, analyzer = analyze_manifests({"requirements.txt": "requests==2.31.0\n"})
    rows = analyzer.coverage(context)
    assert {row["rule_id"] for row in rows} == {
        "DEP-KNOWN-VULNERABILITY",
        "DEP-DUPLICATE-VERSION",
        "DEP-HIGH-DEPENDENCY-COUNT",
        "DEP-UNUSED-CANDIDATE",
    }
    assert all(row["status"] == "supported" for row in rows)
    _, empty_context, empty_analyzer = analyze_manifests({})
    assert all(row["status"] == "unsupported" for row in empty_analyzer.coverage(empty_context))


def test_failed_manifest_coverage_is_failed() -> None:
    _, context, analyzer = analyze_manifests({"package.json": "{oops"})
    assert all(row["status"] == "failed" for row in analyzer.coverage(context))


def test_analyzer_runs_without_osv_client() -> None:
    result, _, _ = analyze_manifests({"requirements.txt": "requests==2.31.0\n"})
    outcome = rule_result(result, "DEP-KNOWN-VULNERABILITY")
    assert outcome.findings == ()
    assert outcome.failure is None
    assert any("could not be obtained" in item.reason for item in outcome.limitations)


def test_rule_failure_isolation() -> None:
    from app.analyzers.dependency.analyzer import build_inventory
    from app.analyzers.rules import RegisteredRule, RuleOutcome
    from tests.fixtures.helpers.analyzer_helpers import make_rule

    def _boom(execution_context) -> RuleOutcome:  # type: ignore[no-untyped-def]
        raise RuntimeError("rule boom")

    class FlakyDependency(DependencyAnalyzer):
        def rules(self) -> list[RegisteredRule]:
            return [
                *super().rules(),
                RegisteredRule(metadata=make_rule("DEP-TEST-999", "dependency"), execute=_boom),
            ]

    ncm = parse_files({})
    context = make_context(ncm=ncm)
    analyzer = FlakyDependency(DictManifestProvider({"requirements.txt": "x==1\n"}))
    result = analyzer.analyze(context)
    by_rule = {item.rule_id: item for item in result.rule_results}
    assert by_rule["DEP-TEST-999"].failure is not None
    assert by_rule["DEP-TEST-999"].findings == ()
    assert result.failed is False
    _ = build_inventory


def test_findings_carry_versions_and_recommendations() -> None:
    result, _, _ = analyze_manifests(
        {
            "requirements.txt": "requests==2.31.0\n",
            "services/api/requirements.txt": "requests==2.28.0\n",
        }
    )
    (finding,) = rule_result(result, "DEP-DUPLICATE-VERSION").findings
    assert finding.analyzer_version == "0.1.0"
    assert finding.rule_set_version == "1.0"
    assert finding.recommendation
    assert finding.location.file_path in ("requirements.txt", "services/api/requirements.txt")
