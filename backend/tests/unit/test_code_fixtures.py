"""Code-structure fixture coverage (TASK-145).

Existing repository fixture areas are consumed as data: the complexity
area must measure, the malformed area must fail without clean results,
and cross-analyzer behavior must stay intact.
"""

from pathlib import Path

from app.analyzers.code_structure.measurements import mccabe_complexity
from app.ncm import NcmRepository
from app.parsers.base import ParserInput
from app.parsers.registry import get_adapter
from tests.fixtures.helpers.code_structure_helpers import analyze_code, rule_result

CODE_STRUCTURE_ROOT = Path(__file__).resolve().parents[3] / "fixtures" / "code-structure"
MALFORMED_ROOT = Path(__file__).resolve().parents[3] / "fixtures" / "malformed"


def _parse(files: dict[str, str]) -> NcmRepository:
    from app.ncm import NcmFileEntry

    adapter = get_adapter("python")
    assert adapter is not None
    entries = []
    for path in sorted(files):
        result = adapter.parse(
            ParserInput(path, "python", files[path].encode("utf-8"), 30.0, 1_000_000)
        )
        entries.append(
            NcmFileEntry(
                path=path, language="python", parse_state=result.state.value, module=result.ncm
            )
        )
    return NcmRepository(analysis_id="analysis-1", files=entries)


def _read_area(root: Path) -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(root.iterdir())
        if path.is_file() and path.suffix == ".py"
    }


def test_code_structure_fixture_area_measures() -> None:
    files = _read_area(CODE_STRUCTURE_ROOT)
    assert files, "code-structure fixture area is empty"
    ncm = _parse(files)
    measured = 0
    for module in ncm.modules:
        for fun in module.functions:
            value = mccabe_complexity(module, fun).measurement.value
            assert value is not None and value >= 1
            measured += 1
    assert measured > 0


def test_malformed_fixture_is_failed_not_clean() -> None:
    candidates = [p for p in MALFORMED_ROOT.iterdir() if p.is_file() and p.suffix == ".py"]
    assert candidates
    path = sorted(candidates)[0]
    result, _, _ = analyze_code({path.name: path.read_text(encoding="utf-8")})
    for rule_id in (
        "CODE-HIGH-COMPLEXITY",
        "CODE-DEEP-NESTING",
        "CODE-HIGH-PARAMETER-COUNT",
        "CODE-DUPLICATE-CANDIDATE",
    ):
        outcome = rule_result(result, rule_id)
        assert any(path.name in item.reason for item in outcome.limitations)


def test_cross_analyzer_regression() -> None:
    """Security, dependency, and architecture behavior is unchanged."""
    from tests.fixtures.helpers.security_helpers import analyze_files as analyze_security

    files = {"m.py": "def work(x):\n    if x:\n        return 1\n    return 0\n"}
    security_result, _, _ = analyze_security(files)
    assert security_result.rule_results
    assert all(finding.category == "security" for finding in security_result.findings)
    from tests.fixtures.helpers.architecture_helpers import analyze_arch

    arch_result, _, _ = analyze_arch(files)
    assert arch_result.rule_results
    assert all(finding.category == "architecture" for finding in arch_result.findings)
    code_result, _, _ = analyze_code(files)
    assert all(finding.category == "code_structure" for finding in code_result.findings)


def test_code_analyzer_does_not_touch_other_domains() -> None:
    from app.analyzers.code_structure.analyzer import CodeStructureAnalyzer
    from app.analyzers.security.source import DictSourceProvider

    analyzer = CodeStructureAnalyzer(DictSourceProvider({}))
    assert analyzer.id == "code_structure"
    assert analyzer.version == "0.1.0"


def test_repository_fixtures_behave_as_shaped() -> None:
    """branchy silent, deep_nesting + many_params fire, small duplicates silent."""
    files = _read_area(CODE_STRUCTURE_ROOT)
    result, _, _ = analyze_code(files)
    assert rule_result(result, "CODE-HIGH-COMPLEXITY").findings == ()
    assert len(rule_result(result, "CODE-DEEP-NESTING").findings) == 1
    assert len(rule_result(result, "CODE-HIGH-PARAMETER-COUNT").findings) == 1
    assert rule_result(result, "CODE-DUPLICATE-CANDIDATE").findings == ()
