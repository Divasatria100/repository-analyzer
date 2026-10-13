"""Unused-dependency candidate tests (TASK-118).

Candidates use conservative wording, Info/Low only, and never claim when
import coverage is missing or the package cannot be mapped reliably.
"""

from tests.fixtures.helpers.dependency_helpers import analyze_manifests, rule_result

SOURCES_WITH_REQUESTS = {"src/app.py": "import requests\nprint(requests.get('https://x.test'))\n"}


def test_dependency_with_recognized_import_is_not_candidate() -> None:
    result, _, _ = analyze_manifests(
        {"requirements.txt": "requests==2.31.0\n"}, SOURCES_WITH_REQUESTS
    )
    assert rule_result(result, "DEP-UNUSED-CANDIDATE").findings == ()


def test_dependency_without_import_is_candidate() -> None:
    result, _, _ = analyze_manifests(
        {"requirements.txt": "requests==2.31.0\nflask==3.0.0\n"}, SOURCES_WITH_REQUESTS
    )
    findings = rule_result(result, "DEP-UNUSED-CANDIDATE").findings
    assert len(findings) == 1
    (finding,) = findings
    assert "flask" in finding.title
    assert finding.severity.value == "Info"
    assert finding.confidence.value == "Low"
    assert "Potentially unused" in finding.description
    assert "manual review required" in finding.description


def test_distribution_name_mapped_to_module() -> None:
    """Pillow is used as ``PIL``: mapping avoids a false candidate."""
    result, _, _ = analyze_manifests(
        {"requirements.txt": "Pillow==10.0.0\n"},
        {"src/img.py": "from PIL import Image\n"},
    )
    assert rule_result(result, "DEP-UNUSED-CANDIDATE").findings == ()


def test_beautifulsoup4_mapped_to_bs4() -> None:
    result, _, _ = analyze_manifests(
        {"requirements.txt": "beautifulsoup4==4.12.0\n"},
        {"src/parse.py": "import bs4\n"},
    )
    assert rule_result(result, "DEP-UNUSED-CANDIDATE").findings == ()


def test_no_python_source_means_no_claim() -> None:
    result, _, _ = analyze_manifests({"requirements.txt": "requests==2.31.0\n"}, {})
    outcome = rule_result(result, "DEP-UNUSED-CANDIDATE")
    assert outcome.findings == ()
    assert any("not evaluated" in item.reason for item in outcome.limitations)


def test_npm_scope_not_evaluated() -> None:
    result, _, _ = analyze_manifests(
        {"package.json": '{"dependencies": {"react": "^18.2.0"}}'},
        SOURCES_WITH_REQUESTS,
    )
    outcome = rule_result(result, "DEP-UNUSED-CANDIDATE")
    assert outcome.findings == ()
    assert any("npm" in item.reason for item in outcome.limitations)


def test_dev_dependency_candidate_wording() -> None:
    result, _, _ = analyze_manifests({"requirements.txt": "pytest==8.0.0\n"}, SOURCES_WITH_REQUESTS)
    (finding,) = rule_result(result, "DEP-UNUSED-CANDIDATE").findings
    assert "Potentially unused" in finding.title or "Potentially unused" in finding.description
    assert finding.confidence.value == "Low"


def test_dynamic_import_signals_noted() -> None:
    sources = {"src/app.py": "import importlib\nmod = importlib.import_module('flask')\n"}
    result, _, _ = analyze_manifests({"requirements.txt": "flask==3.0.0\n"}, sources)
    outcome = rule_result(result, "DEP-UNUSED-CANDIDATE")
    # importlib.import_module('flask') is a dynamic signal, not a static import:
    # either a cautious candidate noting dynamic loading, or no finding.
    for finding in outcome.findings:
        assert "dynamic" in finding.description


def test_transitive_dependencies_never_candidates() -> None:
    lock = (
        '[[package]]\nname = "flask"\nversion = "3.0.0"\n'
        '[package.dependencies]\nwerkzeug = ">=3.0"\n'
        '[[package]]\nname = "werkzeug"\nversion = "3.0.1"\n'
    )
    result, _, _ = analyze_manifests(
        {
            "pyproject.toml": '[project]\nname="d"\ndependencies=["flask==3.0.0"]\n',
            "poetry.lock": lock,
        },
        SOURCES_WITH_REQUESTS,
    )
    titles = [item.title for item in rule_result(result, "DEP-UNUSED-CANDIDATE").findings]
    assert not any("werkzeug" in title for title in titles)
