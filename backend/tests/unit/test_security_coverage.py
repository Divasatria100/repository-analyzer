"""Security coverage tests (TASK-095).

Coverage states must stay explicit and distinguishable: covered,
partially_covered, unsupported, not_applicable, and failed never
collapse into each other, and none of them reads as "secure".
"""

from app.analyzers.security.analyzer import SecurityAnalyzer
from app.analyzers.security.coverage import (
    CoverageStatus,
    coverage_for,
    summarize_scope,
)
from app.analyzers.security.metadata import SECURITY_RULE_SPECS, SPEC_BY_RULE_ID
from app.analyzers.security.source import DictSourceProvider
from app.ncm import NcmFileEntry, NcmRepository
from tests.fixtures.helpers.analyzer_helpers import make_context, make_module
from tests.fixtures.helpers.security_helpers import analyze_files, parse_files


def test_all_rules_have_complete_metadata() -> None:
    """Every V1.0 security rule declares the full metadata contract."""
    assert {spec.rule_id for spec in SECURITY_RULE_SPECS} == {
        "SEC-SQL-INJECTION",
        "SEC-COMMAND-INJECTION",
        "SEC-PATH-TRAVERSAL",
        "SEC-SSRF",
        "SEC-UNSAFE-DESERIALIZATION",
        "SEC-DANGEROUS-DYNAMIC-EXECUTION",
        "SEC-WEAK-CRYPTO",
        "SEC-DISABLED-TLS",
        "SEC-INSECURE-CORS",
    }
    expected_subcategories = {
        "SEC-SQL-INJECTION": "injection",
        "SEC-COMMAND-INJECTION": "injection",
        "SEC-PATH-TRAVERSAL": "injection",
        "SEC-SSRF": "injection",
        "SEC-UNSAFE-DESERIALIZATION": "injection",
        "SEC-DANGEROUS-DYNAMIC-EXECUTION": "injection",
        "SEC-WEAK-CRYPTO": "cryptography",
        "SEC-DISABLED-TLS": "transport-security",
        "SEC-INSECURE-CORS": "configuration",
    }
    for spec in SECURITY_RULE_SPECS:
        assert spec.name.strip()
        assert spec.subcategory == expected_subcategories[spec.rule_id]
        assert spec.description.strip()
        assert spec.default_severity in ("Critical", "High", "Medium", "Low", "Info")
        assert spec.supported_languages == ("python",)
        assert spec.supported_sinks
        assert spec.supported_sources
        assert spec.coverage_notes.strip()
        assert spec.recommendation.strip()
        metadata = spec.to_metadata("1.0")
        assert metadata.rule_id == spec.rule_id
        assert metadata.analyzer_id == "security"
        assert metadata.category == "security"
        assert SPEC_BY_RULE_ID[spec.rule_id] is spec


def test_unsupported_language_does_not_become_clean() -> None:
    """JavaScript-only content: no findings, but explicit unsupported state."""
    ncm = NcmRepository(
        analysis_id="analysis-1",
        files=[
            NcmFileEntry(
                path="notes.js",
                language="javascript",
                parse_state="unsupported",
                module=None,
            )
        ],
    )
    context = make_context(ncm=ncm)
    analyzer = SecurityAnalyzer(DictSourceProvider({}))
    result = analyzer.analyze(context)
    assert result.findings == ()
    assert result.failed is False
    for item in result.rule_results:
        assert item.findings == ()
        assert item.limitations, "unsupported scope must be recorded, never silent"
    coverages = {item.rule_id: item.status for item in analyzer.coverage(ncm)}
    assert set(coverages.values()) == {CoverageStatus.UNSUPPORTED}


def test_parser_failure_does_not_become_clean() -> None:
    """A failed Python file is recorded; surviving findings are preserved."""
    broken = NcmRepository(
        analysis_id="analysis-1",
        files=[
            NcmFileEntry(path="broken.py", language="python", parse_state="failed", module=None),
            NcmFileEntry(
                path="good.py",
                language="python",
                parse_state="parsed",
                module=make_module("good.py"),
            ),
        ],
    )
    context = make_context(ncm=broken)
    analyzer = SecurityAnalyzer(DictSourceProvider({"good.py": "x = 1\n"}))
    result = analyzer.analyze(context)
    assert result.failed is False
    for item in result.rule_results:
        paths = [lim.path for lim in item.limitations]
        assert "broken.py" in paths


def test_partial_representation_reduces_confidence_and_coverage() -> None:
    """Partial modules cap confidence at Medium and mark partial coverage."""
    ncm = parse_files(
        {
            "app.py": (
                "import sys\n"
                "import sqlite3\n"
                "name = sys.argv[1]\n"
                "conn = sqlite3.connect('x')\n"
                "conn.execute('SELECT * FROM u WHERE n = ' + name)\n"
            )
        }
    )
    entry = next(item for item in ncm.files if item.path == "app.py")
    assert entry.module is not None
    entry.module.completeness = "partially"
    scope = summarize_scope(ncm)
    assert scope.partial_modules == ("app.py",)
    coverage = coverage_for("SEC-SQL-INJECTION", scope, sinks_found=True)
    assert coverage.status is CoverageStatus.PARTIALLY_COVERED

    context = make_context(ncm=ncm)
    files = {
        "app.py": (
            "import sys\n"
            "import sqlite3\n"
            "name = sys.argv[1]\n"
            "conn = sqlite3.connect('x')\n"
            "conn.execute('SELECT * FROM u WHERE n = ' + name)\n"
        )
    }
    result = SecurityAnalyzer(DictSourceProvider(files)).analyze(context)
    findings = [f for f in result.findings if f.rule_id == "SEC-SQL-INJECTION"]
    assert len(findings) == 1
    assert findings[0].confidence.value == "Medium"


def test_not_applicable_is_explicit() -> None:
    """Supported content without sinks: recorded, not presented as secure."""
    result, context, analyzer = analyze_files({"app.py": "def add(a, b):\n    return a + b\n"})
    assert result.findings == ()
    coverages = {item.rule_id: item.status for item in analyzer.coverage(context.ncm)}
    assert set(coverages.values()) == {CoverageStatus.NOT_APPLICABLE}
    for item in result.rule_results:
        assert any("no applicable sink" in lim.reason for lim in item.limitations)


def test_coverage_vocabulary_is_complete() -> None:
    """The five states exist and unsupported differs from failed."""
    assert {status.value for status in CoverageStatus} == {
        "covered",
        "partially_covered",
        "unsupported",
        "not_applicable",
        "failed",
    }
    assert CoverageStatus.UNSUPPORTED is not CoverageStatus.FAILED


def test_coverage_serialization_is_deterministic() -> None:
    """Coverage records serialize with stable keys and values."""
    ncm = parse_files({"app.py": "x = 1\n"})
    scope = summarize_scope(ncm)
    first = coverage_for("SEC-SSRF", scope, sinks_found=False).to_dict()
    second = coverage_for("SEC-SSRF", scope, sinks_found=False).to_dict()
    assert (
        first
        == second
        == {
            "rule_id": "SEC-SSRF",
            "status": "not_applicable",
            "reason": first["reason"],
        }
    )
