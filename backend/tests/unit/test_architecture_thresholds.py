"""Architecture threshold tests (TASK-131).

Every frozen threshold uses strict `>` from the centralized ThresholdSet:
below stays silent, equal stays silent, above fires. Severities follow the
§11.1 baseline mapping (Low; Medium when aggravated).
"""

import pytest

from app.analyzers.thresholds import ThresholdSet, default_thresholds
from tests.fixtures.helpers.architecture_helpers import analyze_arch, rule_result

THRESHOLDS = {
    "fan_out": 7,
    "fan_in": 10,
    "coupling": 12,
    "module_lines": 500,
    "module_declarations": 30,
    "class_lines": 200,
    "class_methods": 10,
    "function_lines": 50,
    "function_complexity": 10,
}


def test_frozen_threshold_values_are_centralized() -> None:
    effective = default_thresholds().effective()
    for name, value in THRESHOLDS.items():
        assert effective[name] == value
        assert getattr(default_thresholds(), name) == value


def _hub_spokes(n: int) -> dict[str, str]:
    files = {f"leaf{i}.py": "X = 1\n" for i in range(n)}
    files["hub.py"] = "".join(f"import leaf{i}\n" for i in range(n))
    return files


@pytest.mark.parametrize("count,expected", [(7, 0), (8, 1), (14, 1)])
def test_fan_out_boundary(count: int, expected: int) -> None:
    result, _, _ = analyze_arch(_hub_spokes(count))
    findings = rule_result(result, "ARCH-HIGH-FAN-OUT").findings
    assert len(findings) == expected
    if findings:
        assert findings[0].applied_thresholds == (("fan_out", 7),)
        assert findings[0].severity.value == ("Medium" if count >= 14 else "Low")


@pytest.mark.parametrize("count,expected", [(10, 0), (11, 1), (20, 1)])
def test_fan_in_boundary(count: int, expected: int) -> None:
    files = {f"user{i}.py": "import shared\n" for i in range(count)}
    files["shared.py"] = "X = 1\n"
    result, _, _ = analyze_arch(files)
    findings = rule_result(result, "ARCH-HIGH-FAN-IN").findings
    assert len(findings) == expected
    if findings:
        assert findings[0].applied_thresholds == (("fan_in", 10),)
        assert findings[0].severity.value == ("Medium" if count >= 20 else "Low")


@pytest.mark.parametrize("extra,expected", [(0, 0), (1, 1)])
def test_coupling_boundary(extra: int, expected: int) -> None:
    # Hub with 7 outgoing + 5 incoming = 12 (silent); one more edge fires.
    files = {f"leaf{i}.py": "X = 1\n" for i in range(7)}
    files.update({f"user{i}.py": "import hub\n" for i in range(5 + extra)})
    files["hub.py"] = "".join(f"import leaf{i}\n" for i in range(7))
    result, _, _ = analyze_arch(files)
    findings = rule_result(result, "ARCH-HIGH-COUPLING").findings
    assert len(findings) == expected
    if findings:
        assert "coupling-def-1" in findings[0].description


def test_coupling_aggravated_at_double_threshold() -> None:
    files = {f"leaf{i}.py": "X = 1\n" for i in range(24)}
    files["hub.py"] = "".join(f"import leaf{i}\n" for i in range(24))
    (finding,) = rule_result(analyze_arch(files)[0], "ARCH-HIGH-COUPLING").findings
    assert finding.severity.value == "Medium"  # 24 >= 2 * 12


@pytest.mark.parametrize("total,expected", [(500, 0), (501, 1), (1001, 1)])
def test_module_lines_boundary(total: int, expected: int) -> None:
    from tests.fixtures.helpers.architecture_helpers import lines_of

    source = f'"""Module."""\n{lines_of(total - 1)}\n'
    assert len(source.splitlines()) == total
    result, _, _ = analyze_arch({"m.py": source})
    findings = rule_result(result, "ARCH-LARGE-MODULE").findings
    assert len(findings) == expected
    if findings:
        assert findings[0].applied_thresholds == (
            ("module_lines", 500),
            ("module_declarations", 30),
        )


@pytest.mark.parametrize("n_methods,expected", [(10, 0), (11, 1)])
def test_class_methods_boundary(n_methods: int, expected: int) -> None:
    methods = "\n".join(f"    def m{i}(self):\n        return {i}" for i in range(n_methods))
    result, _, _ = analyze_arch({"m.py": f"class Big:\n{methods}\n"})
    assert len(rule_result(result, "ARCH-LARGE-CLASS").findings) == expected


@pytest.mark.parametrize("n_ifs,expected", [(9, 0), (10, 1)])
def test_function_complexity_boundary(n_ifs: int, expected: int) -> None:
    branches = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(n_ifs))
    result, _, _ = analyze_arch({"m.py": f"def work(x):\n{branches}    return -1\n"})
    findings = rule_result(result, "ARCH-LARGE-FUNCTION").findings
    assert len(findings) == expected
    if findings:
        # Complexity-only trigger: sound (lower bound) but Medium confidence.
        assert findings[0].confidence.value == "Medium"


def test_no_architecture_score_mechanism() -> None:
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "app" / "analyzers" / "architecture"
    text = "\n".join(path.read_text(encoding="utf-8") for path in sorted(root.rglob("*.py")))
    lowered = text.lower()
    for forbidden in (
        "architecture_score",
        "health_percentage",
        "health_score",
        "quality_score",
        "overall_score",
        "letter grade",
        "ranking",
    ):
        assert forbidden not in lowered


def test_threshold_set_rejects_invalid_overrides() -> None:
    with pytest.raises(ValueError):
        ThresholdSet(fan_out=-1)
