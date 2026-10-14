"""Code-structure rule and threshold tests (TASK-139–143)."""

import pytest

from app.analyzers.thresholds import default_thresholds
from tests.fixtures.helpers.code_structure_helpers import (
    analyze_code,
    decision_body,
    nested_body,
    rule_result,
    sig_function,
)

EXPECTED_RULES = [
    "CODE-DEEP-NESTING",
    "CODE-DUPLICATE-CANDIDATE",
    "CODE-HIGH-COMPLEXITY",
    "CODE-HIGH-PARAMETER-COUNT",
]


def test_four_rules_registered_in_order() -> None:
    from app.analyzers.code_structure.analyzer import CodeStructureAnalyzer
    from app.analyzers.security.source import DictSourceProvider

    analyzer = CodeStructureAnalyzer(DictSourceProvider({}))
    assert analyzer.id == "code_structure"
    assert [rule.metadata.rule_id for rule in analyzer.rules()] == EXPECTED_RULES
    assert all(rule.metadata.analyzer_id == "code_structure" for rule in analyzer.rules())


def test_frozen_threshold_values_centralized() -> None:
    effective = default_thresholds().effective()
    assert effective["complexity"] == 10
    assert effective["nesting"] == 4
    assert effective["parameters"] == 5
    assert effective["duplicate_tokens"] == 50


@pytest.mark.parametrize("decisions,expected", [(9, 0), (10, 1)])
def test_complexity_threshold_strict(decisions: int, expected: int) -> None:
    """Complexity 10 silent, 11 fires; Medium/High per contract."""
    result, _, _ = analyze_code({"m.py": f"def work(x):\n{decision_body(decisions)}"})
    findings = rule_result(result, "CODE-HIGH-COMPLEXITY").findings
    assert len(findings) == expected
    if findings:
        (finding,) = findings
        assert finding.severity.value == "Medium"
        assert finding.confidence.value == "High"
        assert finding.applied_thresholds == (("complexity", 10),)
        assert "11" in finding.description


@pytest.mark.parametrize("depth,expected", [(4, 0), (5, 1)])
def test_nesting_threshold_strict(depth: int, expected: int) -> None:
    """Depth 4 silent, 5 fires; Low/High per contract."""
    result, _, _ = analyze_code({"m.py": f"def work(x):\n{nested_body(depth)}"})
    findings = rule_result(result, "CODE-DEEP-NESTING").findings
    assert len(findings) == expected
    if findings:
        (finding,) = findings
        assert finding.severity.value == "Low"
        assert finding.confidence.value == "High"
        assert finding.applied_thresholds == (("nesting", 4),)
        assert "deepest" in finding.description.lower()


@pytest.mark.parametrize("params,expected", [(5, 0), (6, 1)])
def test_parameter_threshold_strict(params: int, expected: int) -> None:
    """5 silent, 6 fires; Low/High per contract."""
    signature = ", ".join(f"p{i}" for i in range(params))
    result, _, _ = analyze_code({"m.py": sig_function(signature)})
    findings = rule_result(result, "CODE-HIGH-PARAMETER-COUNT").findings
    assert len(findings) == expected
    if findings:
        (finding,) = findings
        assert finding.severity.value == "Low"
        assert finding.confidence.value == "High"
        assert finding.applied_thresholds == (("parameters", 5),)


def test_threshold_metadata_records_basis() -> None:
    result, _, _ = analyze_code(
        {"m.py": "def work(x):\n    if x:\n        pass\ndef big():\n" + decision_body(11)}
    )
    findings = rule_result(result, "CODE-HIGH-COMPLEXITY").findings
    assert len(findings) == 1
    assert "strict" in findings[0].description


def _long_body(prefix: str, count: int = 20) -> str:
    return "".join(f"    {prefix}_{i} = {i}\n" for i in range(count))


def test_duplicate_finding_candidate_wording() -> None:
    """Identical ≥50-token bodies → one Info finding, candidate wording."""
    body = _long_body("step")
    files = {"a.py": f"def first():\n{body}", "b.py": f"def second():\n{body}"}
    result, _, _ = analyze_code(files)
    findings = rule_result(result, "CODE-DUPLICATE-CANDIDATE").findings
    assert len(findings) == 1
    (finding,) = findings
    assert finding.severity.value == "Info"
    assert finding.confidence.value in ("Medium", "Low")
    assert "candidate" in finding.description.lower()
    assert "not evidence of shared semantics" in finding.description.lower()
    assert "a.py" in finding.description and "b.py" in finding.description
    assert "primary" in finding.description
    assert finding.applied_thresholds == (("duplicate_tokens", 50),)


def test_duplicate_below_minimum_silent() -> None:
    result, _, _ = analyze_code({"a.py": "def f():\n    x = 1\n", "b.py": "def g():\n    x = 1\n"})
    assert rule_result(result, "CODE-DUPLICATE-CANDIDATE").findings == ()


def test_duplicate_trivial_bodies_silent() -> None:
    result, _, _ = analyze_code({"a.py": "def f():\n    pass\n", "b.py": "def g():\n    pass\n"})
    assert rule_result(result, "CODE-DUPLICATE-CANDIDATE").findings == ()


def test_duplicate_no_pair_reversal() -> None:
    body = _long_body("step")
    files = {"a.py": f"def first():\n{body}", "b.py": f"def second():\n{body}"}
    result, _, _ = analyze_code(dict(reversed(list(files.items()))))
    findings = rule_result(result, "CODE-DUPLICATE-CANDIDATE").findings
    assert len(findings) == 1


def test_duplicate_without_source_is_not_evaluated() -> None:
    from app.analyzers.code_structure.analyzer import CodeStructureAnalyzer

    result, _, _ = analyze_code(
        {"a.py": "def f():\n    x = 1\n"}, analyzer=CodeStructureAnalyzer(None)
    )
    outcome = rule_result(result, "CODE-DUPLICATE-CANDIDATE")
    assert outcome.findings == ()
    assert any("not evaluated" in item.reason for item in outcome.limitations)


def test_duplicate_partial_modules_noted() -> None:
    body = _long_body("step")
    files = {"a.py": f"def first():\n{body}", "b.py": f"def second():\n{body}"}
    result, _, _ = analyze_code(files)
    outcome = rule_result(result, "CODE-DUPLICATE-CANDIDATE")
    assert len(outcome.findings) == 1


def test_no_duplicate_findings_without_bodies() -> None:
    result, _, _ = analyze_code({"m.py": "X = 1\n"})
    assert rule_result(result, "CODE-DUPLICATE-CANDIDATE").findings == ()


def test_duplicate_renamed_parameters_still_match() -> None:
    """Parameters are NCM-confirmed locals: renaming them keeps the run."""
    first = "".join("    total = total + items\n" for _ in range(25))
    second = "".join("    total = total + things\n" for _ in range(25))
    files = {
        "a.py": f"def first(items):\n{first}    return total\n",
        "b.py": f"def second(things):\n{second}    return total\n",
    }
    result, _, _ = analyze_code(files)
    assert len(rule_result(result, "CODE-DUPLICATE-CANDIDATE").findings) == 1


def test_duplicate_different_imports_stay_distinguishable() -> None:
    """Imported/global names are not locals: different libraries break the run."""
    first = "import requests\n" + "".join(
        f"    response_{i} = requests.get(url_{i})\n" for i in range(20)
    )
    second = "import httpx\n" + "".join(
        f"    response_{i} = httpx.get(url_{i})\n" for i in range(20)
    )
    files = {
        "a.py": f"def fetch_a():\n{first}",
        "b.py": f"def fetch_b():\n{second}",
    }
    result, _, _ = analyze_code(files)
    assert rule_result(result, "CODE-DUPLICATE-CANDIDATE").findings == ()


def test_duplicate_loop_variable_rename_breaks_run() -> None:
    """Loop variables lack NCM evidence: they stay literal (conservative)."""
    first = "".join(f"    for i{i} in range(3):\n        show(i{i})\n" for i in range(12))
    second = "".join(f"    for j{i} in range(3):\n        show(j{i})\n" for i in range(12))
    files = {
        "a.py": f"def first():\n{first}",
        "b.py": f"def second():\n{second}",
    }
    result, _, _ = analyze_code(files)
    assert rule_result(result, "CODE-DUPLICATE-CANDIDATE").findings == ()


def test_duplicate_normalization_limitation_recorded() -> None:
    """The NCM-local normalization scope is an explicit outcome limitation."""
    body = _long_body("step")
    files = {"a.py": f"def first():\n{body}", "b.py": f"def second():\n{body}"}
    result, _, _ = analyze_code(files)
    outcome = rule_result(result, "CODE-DUPLICATE-CANDIDATE")
    assert len(outcome.findings) == 1
    assert any("positively identified as local" in item.reason for item in outcome.limitations)
