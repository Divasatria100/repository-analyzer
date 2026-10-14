"""Code-structure analyzer integration tests (TASK-140–145 integration).

Common foundation, deterministic identity, bounded redacted evidence,
failure isolation, coverage states, hotspot traceability, and cross-domain
measurement identity (PIPE-REQ-054).
"""

from app.analyzers.code_structure.analyzer import CodeStructureAnalyzer
from app.analyzers.security.source import DictSourceProvider
from tests.fixtures.helpers.code_structure_helpers import analyze_code, rule_result

EXPECTED_RULES = [
    "CODE-DEEP-NESTING",
    "CODE-DUPLICATE-CANDIDATE",
    "CODE-HIGH-COMPLEXITY",
    "CODE-HIGH-PARAMETER-COUNT",
]


def test_only_code_structure_rules_run() -> None:
    result, _, _ = analyze_code(
        {"m.py": "def work(x):\n    if x:\n        return 1\n    return 0\n"}
    )
    assert {item.rule_id for item in result.rule_results} == set(EXPECTED_RULES)
    assert all(finding.category == "code_structure" for finding in result.findings)


def test_finding_identities_are_deterministic() -> None:
    from tests.fixtures.helpers.code_structure_helpers import decision_body

    files = {"m.py": f"def work(x):\n{decision_body(11)}"}
    first, _, _ = analyze_code(files)
    second, _, _ = analyze_code(files)
    assert {item.identity_key for item in first.findings} == {
        item.identity_key for item in second.findings
    }
    assert first.findings


def test_evidence_bounded_and_redacted() -> None:
    source = 'password = "FAKE-CODE-PASSWORD-NOT-REAL-1"\n' + "".join(
        f"def f{i}(a, b, c, d, e, f):\n    return {i}\n" for i in range(3)
    )
    result, _, _ = analyze_code({"m.py": source})
    findings = rule_result(result, "CODE-HIGH-PARAMETER-COUNT").findings
    assert len(findings) == 3
    for finding in findings:
        assert finding.evidence is not None
        assert len(finding.evidence.lines) <= 51
        for line in finding.evidence.lines:
            assert "FAKE-CODE-PASSWORD-NOT-REAL-1" not in line


def test_partial_analysis_is_not_clean() -> None:
    result, _, _ = analyze_code({"good.py": "X = 1\n", "broken.py": "def broken(:\n"})
    for rule_id in EXPECTED_RULES:
        outcome = rule_result(result, rule_id)
        assert any("broken.py" in item.reason for item in outcome.limitations)


def test_unsupported_repository_is_not_clean() -> None:
    from app.ncm import NcmFileEntry, NcmRepository
    from tests.fixtures.helpers.analyzer_helpers import make_context

    ncm = NcmRepository(
        analysis_id="analysis-1",
        files=[
            NcmFileEntry(path="a.js", language="javascript", parse_state="unsupported", module=None)
        ],
    )
    context = make_context(ncm=ncm)
    analyzer = CodeStructureAnalyzer(DictSourceProvider({}))
    rows = {item.rule_id: item.status.value for item in analyzer.coverage(ncm)}
    assert set(rows.values()) == {"unsupported"}
    _ = context


def test_rule_failure_isolation() -> None:
    from app.analyzers.rules import RegisteredRule, RuleOutcome
    from tests.fixtures.helpers.analyzer_helpers import make_rule

    def _boom(execution_context) -> RuleOutcome:  # type: ignore[no-untyped-def]
        raise RuntimeError("rule boom")

    class FlakyCode(CodeStructureAnalyzer):
        def rules(self) -> list[RegisteredRule]:
            return [
                *super().rules(),
                RegisteredRule(
                    metadata=make_rule("CODE-TEST-999", "code_structure"), execute=_boom
                ),
            ]

    result, _, _ = analyze_code(
        {"m.py": "def f(a, b, c, d, e, f):\n    pass\n"},
        analyzer=FlakyCode(DictSourceProvider({"m.py": "x"})),
    )
    by_rule = {item.rule_id: item for item in result.rule_results}
    assert by_rule["CODE-TEST-999"].failure is not None
    assert by_rule["CODE-TEST-999"].findings == ()
    assert result.failed is False
    assert "CODE-HIGH-PARAMETER-COUNT" in {item.rule_id for item in result.findings}


def test_no_duplicate_rule_results() -> None:
    from tests.fixtures.helpers.code_structure_helpers import decision_body

    result, _, _ = analyze_code({"m.py": f"def work(x):\n{decision_body(11)}"})
    keys = [item.identity_key for item in result.findings]
    assert len(keys) == len(set(keys))


def test_shared_measurements_identical_across_domains() -> None:
    """PIPE-REQ-054: architecture and code-structure complexity agree."""
    from app.analyzers.architecture.metrics import function_complexity_lower_bound
    from app.analyzers.code_structure.measurements import mccabe_complexity
    from tests.fixtures.helpers.security_helpers import parse_files

    source = "def work(x):\n    if x:\n        pass\n    for i in range(2):\n        pass\n"
    (module,) = parse_files({"m.py": source}).modules
    (fun,) = module.functions
    code_value = mccabe_complexity(module, fun).measurement.value
    arch_value = function_complexity_lower_bound(module, fun).value
    assert code_value == arch_value == 3


def test_hotspots_traceable_without_scores() -> None:
    from tests.fixtures.helpers.code_structure_helpers import decision_body

    body = decision_body(11)
    nested = (
        "    if a:\n        if b:\n            if c:\n"
        "                if d:\n                    if e:\n                        pass\n"
    )
    source = f"def hot(x):\n{body}{nested}    return 0\n"
    result, context, analyzer = analyze_code({"m.py": source})
    hotspots = analyzer.hotspots(context)
    assert len(hotspots) == 1
    (hotspot,) = hotspots
    assert hotspot.path == "m.py"
    assert hotspot.symbol == "m.hot"
    assert hotspot.signal_count == 2
    rules = {item["rule_id"] for item in hotspot.measurements}
    assert rules == {"CODE-HIGH-COMPLEXITY", "CODE-DEEP-NESTING"}
    finding_ids = {item.identity_key for item in result.findings}
    assert set(hotspot.finding_ids) <= finding_ids
    import json

    text = json.dumps(
        [
            {
                "path": item.path,
                "symbol": item.symbol,
                "signal_count": item.signal_count,
                "measurements": list(item.measurements),
                "finding_ids": list(item.finding_ids),
            }
            for item in hotspots
        ]
    )
    lowered = text.lower()
    assert "score" not in lowered
    assert "rank" not in lowered
    assert "weight" not in lowered
    assert "grade" not in lowered


def test_hotspot_ordering_and_empty_cases() -> None:
    from app.analyzers.code_structure.hotspots import build_hotspots

    assert build_hotspots([]) == []
    result, context, analyzer = analyze_code({"m.py": "def tiny():\n    pass\n"})
    assert analyzer.hotspots(context) == []
    _ = result


def test_hotspot_tiebreak_deterministic() -> None:
    _, context, analyzer = analyze_code(
        {
            "b.py": "def f(a, b, c, d, e, f):\n    pass\n",
            "a.py": "def g(a, b, c, d, e, f):\n    pass\n",
        }
    )
    hotspots = analyzer.hotspots(context)
    assert [(item.path, item.symbol) for item in hotspots] == [("a.py", "a.g"), ("b.py", "b.f")]
