"""Canonical result serialization unit tests (Phase 11, TASK-161).

Hand-built snapshot rows (transient ORM objects, no session): section
presence rules, summary consistency, vocabulary mappings, measurement
resolution, and failure modes. No database, no network.
"""

from datetime import UTC, datetime

import pytest

from app.models.indexing import File, Limitation
from app.models.repository import Analysis, Repository
from app.models.results import (
    AnalysisSnapshot,
    ArchitectureMetric,
    Dependency,
    DependencyAdvisory,
    DomainState,
    Finding,
    FindingDependency,
    FindingLocation,
    FindingModule,
    Module,
    ModuleDependency,
    RuleEvaluation,
)
from app.results.canonical import SnapshotData, build_canonical_result


def _analysis(**overrides: object) -> Analysis:
    values: dict[str, object] = {
        "id": "a" * 32,
        "repository_id": "r" * 32,
        "resolved_branch": "main",
        "branch_origin": "defaulted",
        "resolved_commit_sha": "c" * 40,
        "commit_origin": "defaulted",
        "stage": "AggregatingResults",
        "outcome": "Completed",
        "analyzer_version": "1.0.0",
        "rule_set_version": "1.0.0",
        "completed_at": datetime(2026, 10, 14, tzinfo=UTC),
        "explanation": "",
        "analysis_config": {"generated_files": "Included", "architecture": {}},
        "advisory_source": "OSV",
        "advisory_consulted_at": None,
        "advisory_status": "succeeded",
        "created_at": datetime(2026, 10, 14, tzinfo=UTC),
    }
    values.update(overrides)
    return Analysis(**values)  # type: ignore[arg-type]


def _repository() -> Repository:
    return Repository(
        id="r" * 32,
        normalized_url="https://github.com/example-org/example-service",
        owner="example-org",
        name="example-service",
    )


def _snapshot() -> AnalysisSnapshot:
    return AnalysisSnapshot(
        id="s" * 32,
        analysis_id="a" * 32,
        sealed_at=datetime(2026, 10, 14, 1, tzinfo=UTC),
        outcome="Completed",
    )


def _file(path: str = "app/main.py", **overrides: object) -> File:
    values: dict[str, object] = {
        "id": f"file-{path}",
        "analysis_id": "a" * 32,
        "path": path,
        "file_type": "source",
        "extension": ".py",
        "size": 100,
        "language": "python",
        "support_status": "supported",
        "is_binary": False,
        "is_generated": False,
        "excluded": False,
        "exclusion_reason": None,
        "eligibility": "eligible",
        "eligibility_reason": None,
        "parse_result": "parsed",
        "diagnostics": [],
        "indexing_limitation": None,
    }
    values.update(overrides)
    return File(**values)  # type: ignore[arg-type]


def _finding(**overrides: object) -> Finding:
    row = Finding(
        id="finding-1",
        analysis_id="a" * 32,
        rule_id="ARCH-HIGH-FAN-OUT",
        rule_set_version="1.0.0",
        category="architecture",
        finding_id="F-0001",
        identity_key="identity-1",
        subject_key="fan-out:app/main.py",
        title="Elevated fan-out",
        description="Module app/main.py has fan_out 5 > 3 (strict).",
        severity="Medium",
        confidence="High",
        location_path="app/main.py",
        start_line=1,
        end_line=1,
        start_column=0,
        end_column=0,
        evidence=None,
        redacted=False,
        recommendation="Review.",
        impact=None,
        severity_factors=["value 5 against threshold 3"],
        confidence_factors=["direct count"],
        applied_thresholds=[["fan_out", 3]],
        partial_info=False,
    )
    for key, value in overrides.items():
        setattr(row, key, value)
    row.locations = [
        FindingLocation(
            id="loc-1",
            finding_id="finding-1",
            path="app/main.py",
            start_line=1,
            end_line=1,
            start_column=0,
            end_column=0,
            primary=True,
        )
    ]
    row.modules = [
        FindingModule(
            id="fm-1",
            finding_id="finding-1",
            module_id="module-1",
            module_node_id="app/main.py",
            module_layer=None,
        )
    ]
    row.dependencies = []
    return row


def _data(**overrides: object) -> SnapshotData:
    values: dict[str, object] = {
        "analysis": _analysis(),
        "repository": _repository(),
        "snapshot": _snapshot(),
        "rules": {"ARCH-HIGH-FAN-OUT": "High fan-out"},
        "findings": [_finding()],
        "rule_evaluations": [
            RuleEvaluation(
                id="re-1",
                analysis_id="a" * 32,
                rule_id="ARCH-HIGH-FAN-OUT",
                rule_set_version="1.0.0",
                state="Evaluated",
                reason=None,
            )
        ],
        "metrics": [
            ArchitectureMetric(
                id="m-1",
                analysis_id="a" * 32,
                area="architecture",
                metric_name="fan_out",
                subject_kind="module",
                subject_path="app/main.py",
                subject_name="",
                value=5,
                availability="available",
            )
        ],
        "modules": [
            Module(
                id="module-1",
                analysis_id="a" * 32,
                module_id="app/main.py",
                file_id="file-app/main.py",
                partially_represented=False,
                layer=None,
            )
        ],
        "module_dependencies": [],
        "dependencies": [],
        "files": [_file()],
        "file_coverages": [],
        "domain_states": [
            DomainState(id=f"ds-{area}", analysis_id="a" * 32, area=area, state=state, reason=None)
            for area, state in (
                ("security", "No findings detected"),
                ("architecture", None),
                ("dependency", "No findings detected"),
                ("code_structure", "No findings detected"),
            )
        ],
        "limitations": [],
        "comparison": None,
    }
    values.update(overrides)
    return SnapshotData(**values)  # type: ignore[arg-type]


def test_full_result_sections_and_summary_consistency() -> None:
    result = build_canonical_result(_data())
    assert result["analysis"]["analysis_id"] == "a" * 32
    assert result["analysis"]["advisory_data"]["outcome"] == "Succeeded"
    assert result["repository"]["analyzed_state"]["branch"] == {
        "name": "main",
        "origin": "Defaulted",
    }
    status = result["status"]
    assert isinstance(status, dict)
    # Exactly one of stage/outcome is non-null for a terminal analysis.
    assert status["stage"] is None and status["outcome"] == "Completed"
    assert status["snapshot"] == {"sealed_at": "2026-10-14T01:00:00Z"}
    architecture = result["architecture"]
    assert isinstance(architecture, dict)
    assert len(architecture["findings"]) == 1
    finding = architecture["findings"][0]
    assert finding["rule_name"] == "High fan-out"
    assert finding["subject"]["modules"] == ["app/main.py"]
    assert finding["evidence"]["measurements"] == [
        {"metric": "fan_out", "value": 5, "exceeded": True}
    ]
    assert finding["applied_thresholds"] == [{"threshold": "fan_out", "value": 3}]
    assert architecture["cycles"] == []
    assert architecture["graph"]["granularity"] == "Source file"
    assert architecture["graph"]["nodes"][0]["node_id"] == "app/main.py"
    summary = result["summary"]
    assert isinstance(summary, dict)
    area_summary = summary["architecture"]
    assert isinstance(area_summary, dict)
    assert area_summary["state"] is None
    assert area_summary["findings"]["total"] == 1
    assert area_summary["findings"]["by_severity"]["Medium"] == 1
    assert area_summary["findings"]["by_rule"] == {"ARCH-HIGH-FAN-OUT": 1}
    assert area_summary["module_count"] == 1
    assert area_summary["cycle_count"] == {"value": 0, "unit": "cycles"}
    assert summary["files"] == {
        "indexed": 1,
        "parse_results": {
            "Parsed": 1,
            "Parsed with diagnostics": 0,
            "Failed": 0,
            "Not parsed": 0,
        },
    }
    assert summary["languages"] == [
        {"language": "Python", "support": "Primary Support", "file_count": 1}
    ]
    files = result["files"]
    assert isinstance(files, list) and len(files) == 1
    assert files[0]["finding_count"] == 1
    assert files[0]["support"] == "Primary Support"
    assert result["comparison"] is None


def test_null_sections_for_unavailable_areas() -> None:
    data = _data(
        findings=[],
        domain_states=[
            DomainState(
                id=f"ds-{area}", analysis_id="a" * 32, area=area, state=state, reason=reason
            )
            for area, state, reason in (
                ("security", "Analysis not performed", "No supported content."),
                ("architecture", "Analysis failed", "Analyzer did not complete."),
                ("dependency", "Analysis unavailable", "No output provided."),
                ("code_structure", "No findings detected", None),
            )
        ],
    )
    result = build_canonical_result(data)
    assert result["security"] is None
    assert result["architecture"] is None
    assert result["dependencies"] is None
    assert result["code_structure"] is not None
    summary = result["summary"]
    assert isinstance(summary, dict)
    assert summary["security"] == {"state": "Analysis not performed", "findings": None}
    assert "module_count" not in summary["architecture"]
    assert "dependency_count" not in summary["dependencies"]


def test_failed_outcome_and_missing_configuration_raise() -> None:
    with pytest.raises(ValueError, match="completed outcome"):
        build_canonical_result(_data(analysis=_analysis(outcome="Failed")))
    with pytest.raises(ValueError, match="configuration"):
        build_canonical_result(_data(analysis=_analysis(analysis_config=None)))


def test_unknown_rule_and_unknown_values_raise() -> None:
    with pytest.raises(ValueError, match="Unknown rule"):
        build_canonical_result(_data(rules={}))
    with pytest.raises(ValueError, match="Unknown file type"):
        build_canonical_result(_data(files=[_file(file_type="mystery")]))
    with pytest.raises(ValueError, match="Unknown support status"):
        build_canonical_result(_data(files=[_file(support_status="mystery")]))
    with pytest.raises(ValueError, match="Unknown metric"):
        build_canonical_result(
            _data(
                metrics=[
                    ArchitectureMetric(
                        id="m-x",
                        analysis_id="a" * 32,
                        area="architecture",
                        metric_name="mystery",
                        subject_path="app/main.py",
                        value=1,
                    )
                ]
            )
        )


def test_cycle_and_dependency_sections() -> None:
    cycle = _finding()
    cycle.rule_id = "ARCH-CIRCULAR-DEPENDENCY"
    cycle.finding_id = "F-0002"
    cycle.identity_key = "identity-2"
    cycle.subject_key = "cycle:app/a.py,app/b.py"
    cycle.modules = [
        FindingModule(
            id="fm-a",
            finding_id="finding-2",
            module_id="m-a",
            module_node_id="app/a.py",
            module_layer=None,
        ),
        FindingModule(
            id="fm-b",
            finding_id="finding-2",
            module_id="m-b",
            module_node_id="app/b.py",
            module_layer=None,
        ),
    ]
    dependency = Dependency(
        id="dep-1",
        analysis_id="a" * 32,
        ecosystem="pypi",
        canonical_name="requests",
        original_name="requests",
        resolved_version="2.28.0",
        source_manifest="requirements.txt",
        dependency_class="direct",
    )
    dependency.relationships = []
    dependency.advisories = [
        DependencyAdvisory(id="da-1", dependency_id="dep-1", advisory_id="GHSA-test", source="OSV")
    ]
    vuln = _finding()
    vuln.id = "finding-3"
    vuln.rule_id = "DEP-KNOWN-VULNERABILITY"
    vuln.category = "dependency"
    vuln.finding_id = "F-0003"
    vuln.identity_key = "identity-3"
    vuln.subject_key = "pypi:requests:2.28.0:GHSA-test"
    vuln.modules = []
    vuln.dependencies = [
        FindingDependency(id="fd-1", finding_id="finding-3", dependency_id="dep-1")
    ]
    data = _data(
        rules={
            "ARCH-HIGH-FAN-OUT": "High fan-out",
            "ARCH-CIRCULAR-DEPENDENCY": "Circular dependency",
            "DEP-KNOWN-VULNERABILITY": "Known vulnerability",
        },
        findings=[cycle, vuln],
        domain_states=[
            DomainState(
                id="ds-security",
                analysis_id="a" * 32,
                area="security",
                state="No findings detected",
                reason=None,
            ),
            DomainState(
                id="ds-architecture",
                analysis_id="a" * 32,
                area="architecture",
                state=None,
                reason=None,
            ),
            DomainState(
                id="ds-dependency", analysis_id="a" * 32, area="dependency", state=None, reason=None
            ),
            DomainState(
                id="ds-code",
                analysis_id="a" * 32,
                area="code_structure",
                state="No findings detected",
                reason=None,
            ),
        ],
        modules=[
            Module(
                id="m-a", analysis_id="a" * 32, module_id="app/a.py", partially_represented=False
            ),
            Module(
                id="m-b", analysis_id="a" * 32, module_id="app/b.py", partially_represented=False
            ),
        ],
        module_dependencies=[
            ModuleDependency(
                id="md-1",
                analysis_id="a" * 32,
                source_id="m-a",
                target_id="m-b",
                target_text="app.b",
                resolution="internal",
                line=2,
                column=0,
            ),
            ModuleDependency(
                id="md-2",
                analysis_id="a" * 32,
                source_id="m-b",
                target_id="m-a",
                target_text="app.a",
                resolution="internal",
                line=4,
                column=0,
            ),
            ModuleDependency(
                id="md-3",
                analysis_id="a" * 32,
                source_id="m-a",
                target_id=None,
                target_text="os",
                resolution="external",
                line=1,
                column=0,
            ),
        ],
        dependencies=[dependency],
        files=[
            _file("app/a.py"),
            _file("app/b.py"),
            _file(
                "requirements.txt",
                id="file-requirements.txt",
                file_type="manifest",
                extension=".txt",
                size=20,
                language=None,
                support_status="unrecognized",
                eligibility="eligible",
                parse_result=None,
            ),
        ],
    )
    result = build_canonical_result(data)
    architecture = result["architecture"]
    assert isinstance(architecture, dict)
    assert architecture["cycles"] == [
        {"finding_id": "F-0002", "node_ids": ["app/a.py", "app/b.py"]}
    ]
    graph = architecture["graph"]
    assert isinstance(graph, dict)
    assert len(graph["edges"]) == 2
    assert len(graph["external_and_unresolved_references"]) == 1
    assert graph["external_and_unresolved_references"][0]["resolution"] == "external"
    summary = result["summary"]
    assert isinstance(summary, dict)
    arch_summary = summary["architecture"]
    assert isinstance(arch_summary, dict)
    assert arch_summary["cycle_count"] == {"value": 1, "unit": "cycles"}
    assert arch_summary["module_dependency_count"] == 2
    dependencies_section = result["dependencies"]
    assert isinstance(dependencies_section, dict)
    assert dependencies_section["items"][0]["advisories"] == [
        {"advisory_id": "GHSA-test", "source": "OSV"}
    ]
    assert dependencies_section["items"][0]["finding_ids"] == ["F-0003"]
    dep_summary = summary["dependencies"]
    assert isinstance(dep_summary, dict)
    assert dep_summary["dependency_count"] == {"total": 1, "direct": 1, "transitive": 0}
    assert dep_summary["vulnerable_count"] == 1


def test_limitation_and_file_entry_shapes() -> None:
    data = _data(
        limitations=[
            Limitation(
                id="lim-1",
                analysis_id="a" * 32,
                scope_kind="rule",
                area="architecture",
                rule_id="ARCH-HIGH-FAN-OUT",
                rule_set_version="1.0.0",
                file_id=None,
                file_path=None,
                reason="Graph may be incomplete.",
            )
        ],
        files=[
            _file(
                excluded=True,
                exclusion_reason="Generated file excluded.",
                eligibility="not_eligible",
                eligibility_reason="Excluded.",
                parse_result="failed",
                diagnostics=[{"code": "E1", "message": "broken", "line": 3, "column": 0}],
                indexing_limitation="Unreadable tail.",
            )
        ],
    )
    result = build_canonical_result(data)
    status = result["status"]
    assert isinstance(status, dict)
    assert status["limitations"] == [
        {
            "scope_kind": "rule",
            "area": "architecture",
            "rule_id": "ARCH-HIGH-FAN-OUT",
            "reason": "Graph may be incomplete.",
        }
    ]
    files = result["files"]
    assert isinstance(files, list)
    assert files[0]["exclusion"] == {"status": "Excluded", "reason": "Generated file excluded."}
    assert files[0]["eligibility"] == {"classification": "Not eligible", "reason": "Excluded."}
    assert files[0]["parse_result"] == "Failed"
    assert files[0]["indexing_limitation"] == "Unreadable tail."
