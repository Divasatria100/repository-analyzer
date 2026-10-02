"""Phase 8 cross-cutting tests: pipeline, isolation, determinism, severity.

Proves the five new rules work through the real SecurityAnalyzer
pipeline (never rule classes in isolation), that one failing rule never
silences its siblings, that output is deterministic, and that every
rule's severity stays inside its frozen range.
"""

from app.analyzers.rules import RegisteredRule, RuleOutcome
from app.analyzers.security.analyzer import SecurityAnalyzer
from app.analyzers.security.coverage import CoverageStatus
from app.analyzers.security.source import DictSourceProvider
from tests.fixtures.helpers.analyzer_helpers import make_rule
from tests.fixtures.helpers.security_helpers import analyze_files

NEW_RULE_IDS = (
    "SEC-UNSAFE-DESERIALIZATION",
    "SEC-DANGEROUS-DYNAMIC-EXECUTION",
    "SEC-WEAK-CRYPTO",
    "SEC-DISABLED-TLS",
    "SEC-INSECURE-CORS",
)

SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

FROZEN_RANGES = {
    "SEC-SQL-INJECTION": ("Medium", "Critical"),
    "SEC-COMMAND-INJECTION": ("Medium", "Critical"),
    "SEC-PATH-TRAVERSAL": ("Low", "High"),
    "SEC-SSRF": ("Low", "High"),
    "SEC-UNSAFE-DESERIALIZATION": ("Medium", "Critical"),
    "SEC-DANGEROUS-DYNAMIC-EXECUTION": ("Low", "Critical"),
    "SEC-WEAK-CRYPTO": ("Info", "High"),
    "SEC-DISABLED-TLS": ("Low", "High"),
    "SEC-INSECURE-CORS": ("Info", "High"),
    "SEC-SENSITIVE-LOGGING": ("Low", "High"),
    "SEC-POTENTIAL-AUTHORIZATION": ("Low", "High"),
    "SEC-HARDCODED-SECRET": ("Medium", "Critical"),
}

PHASE8_APP = {
    "app.py": (
        "import hashlib\n"
        "import pickle\n"
        "import requests\n"
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "\n"
        "def handle(request, password):\n"
        "    obj = pickle.loads(request.body())\n"
        "    digest = hashlib.md5(password.encode()).hexdigest()\n"
        "    requests.get(request.args['url'], verify=False)\n"
        "    return eval(request.args['expr'])\n"
        "\n"
        "def configure(app):\n"
        "    app.add_middleware(CORSMiddleware, allow_origins=['*'])\n"
    )
}


def test_all_five_new_rules_fire_through_pipeline() -> None:
    """Every new rule executes through SecurityAnalyzer, not in isolation."""
    result, _, _ = analyze_files(PHASE8_APP)
    assert result.failed is False
    assert set(NEW_RULE_IDS) <= {finding.rule_id for finding in result.findings}
    assert len(result.rule_results) == 12


def test_new_rule_failure_does_not_stop_siblings() -> None:
    """A crashing new rule is recorded; all other findings survive."""

    def _boom(execution_context) -> RuleOutcome:  # type: ignore[no-untyped-def]
        raise RuntimeError("weak crypto boom")

    from app.analyzers.security.metadata import SPEC_BY_RULE_ID
    from app.analyzers.versioning import RULE_SET_VERSION

    class FlakySecurity(SecurityAnalyzer):
        def rules(self) -> list[RegisteredRule]:
            kept = [rule for rule in super().rules() if rule.metadata.rule_id != "SEC-WEAK-CRYPTO"]
            metadata = SPEC_BY_RULE_ID["SEC-WEAK-CRYPTO"].to_metadata(RULE_SET_VERSION)
            return [*kept, RegisteredRule(metadata=metadata, execute=_boom)]

    result, _, _ = analyze_files(PHASE8_APP, analyzer=FlakySecurity(DictSourceProvider(PHASE8_APP)))
    by_rule = {item.rule_id: item for item in result.rule_results}
    assert by_rule["SEC-WEAK-CRYPTO"].failure is not None
    assert by_rule["SEC-WEAK-CRYPTO"].findings == ()
    assert result.failed is False
    surviving = {finding.rule_id for finding in result.findings}
    assert set(NEW_RULE_IDS) - {"SEC-WEAK-CRYPTO"} <= surviving
    assert "SEC-SQL-INJECTION" not in surviving  # no SQL sinks in this app
    failed_coverages = [item for item in result.rule_results if item.failure is not None]
    assert len(failed_coverages) == 1
    assert failed_coverages[0].rule_id == "SEC-WEAK-CRYPTO"


def test_failed_new_rule_is_never_clean() -> None:
    """A failed rule contributes a failure record, not zero findings."""
    result, _, _ = analyze_files(PHASE8_APP)
    for item in result.rule_results:
        if item.failure is not None:
            assert item.findings == ()
            assert item.failure.rule_id == item.rule_id


def test_phase8_output_is_deterministic() -> None:
    """Repeated analysis agrees on findings, identity, order, coverage."""
    first, first_context, first_analyzer = analyze_files(PHASE8_APP)
    second, second_context, second_analyzer = analyze_files(PHASE8_APP)
    assert [f.identity_key for f in first.findings] == [f.identity_key for f in second.findings]
    assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]
    first_coverage = {
        item.rule_id: item.status for item in first_analyzer.coverage(first_context.ncm)
    }
    second_coverage = {
        item.rule_id: item.status for item in second_analyzer.coverage(second_context.ncm)
    }
    assert first_coverage == second_coverage
    rule_sequence = [finding.rule_id for finding in first.findings]
    assert rule_sequence == sorted(rule_sequence)
    for rule_id in set(rule_sequence):
        locations = [
            (finding.location.start_line, finding.location.start_column)
            for finding in first.findings
            if finding.rule_id == rule_id
        ]
        assert locations == sorted(locations)


def test_no_duplicate_identities_across_new_rules() -> None:
    """The same logical issue is never reported twice by one rule."""
    result, _, _ = analyze_files(PHASE8_APP)
    keys = [finding.identity_key for finding in result.findings]
    assert len(keys) == len(set(keys))


def test_all_rules_stay_within_frozen_severity_ranges() -> None:
    """Every finding's severity lies inside its rule's frozen range."""
    from app.analyzers.security.metadata import SPEC_BY_RULE_ID

    assert set(SPEC_BY_RULE_ID) == set(FROZEN_RANGES)
    result, _, _ = analyze_files(PHASE8_APP)
    assert result.findings
    for finding in result.findings:
        low, high = FROZEN_RANGES[finding.rule_id]
        assert SEVERITY_RANK[low] <= SEVERITY_RANK[finding.severity.value] <= SEVERITY_RANK[high], (
            finding.rule_id,
            finding.severity.value,
        )
    for rule_id, spec in SPEC_BY_RULE_ID.items():
        low, high = FROZEN_RANGES[rule_id]
        assert SEVERITY_RANK[low] <= SEVERITY_RANK[spec.default_severity] <= SEVERITY_RANK[high]


def test_new_rules_report_explicit_coverage() -> None:
    """New rules distinguish covered from not_applicable; never clean-silence."""
    result, context, analyzer = analyze_files(PHASE8_APP)
    assert result.findings
    coverages = {item.rule_id: item.status for item in analyzer.coverage(context.ncm)}
    for rule_id in NEW_RULE_IDS:
        assert coverages[rule_id] is CoverageStatus.COVERED
    quiet, quiet_context, quiet_analyzer = analyze_files(
        {"app.py": "def add(a, b):\n    return a + b\n"}
    )
    assert quiet.findings == ()
    quiet_coverages = {
        item.rule_id: item.status for item in quiet_analyzer.coverage(quiet_context.ncm)
    }
    # Repository-wide secret scanning still runs (and stays silent) on this
    # file; every other rule has no applicable sink pattern.
    assert quiet_coverages["SEC-HARDCODED-SECRET"] is CoverageStatus.COVERED
    assert {
        status for rule, status in quiet_coverages.items() if rule != "SEC-HARDCODED-SECRET"
    } == {CoverageStatus.NOT_APPLICABLE}
    for item in quiet.rule_results:
        if item.rule_id == "SEC-HARDCODED-SECRET":
            assert item.limitations == ()
        else:
            assert item.limitations


def test_cross_rule_overlap_without_duplication() -> None:
    """pickle→eval chains raise both rules; subprocess stays single-ruled."""
    result, _, _ = analyze_files(
        {
            "app.py": (
                "import pickle\n"
                "import subprocess\n"
                "def handle(data, host):\n"
                "    obj = pickle.loads(data)\n"
                "    eval(obj)\n"
                "    subprocess.run('ping ' + host, shell=True)\n"
            )
        }
    )
    by_rule: dict[str, int] = {}
    for finding in result.findings:
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
    assert by_rule.get("SEC-UNSAFE-DESERIALIZATION") == 1
    assert by_rule.get("SEC-DANGEROUS-DYNAMIC-EXECUTION") == 1
    assert by_rule.get("SEC-COMMAND-INJECTION") == 1
    assert sum(by_rule.values()) == 3


def test_source_provider_contract_unchanged() -> None:
    """SourceProvider stays bounded, data-only, and non-parsing."""
    from app.analyzers.security.source import (
        MAX_SOURCE_BYTES,
        DictSourceProvider,
        SourceFile,
    )

    assert MAX_SOURCE_BYTES == 1024 * 1024
    provider = DictSourceProvider({"app.py": "x = 1\n"})
    source = provider.read("app.py")
    assert isinstance(source, SourceFile)
    assert source.lines == ("x = 1",)
    assert provider.read("missing.py") is None
    big = DictSourceProvider({"big.py": "x\n" * (MAX_SOURCE_BYTES // 2)})
    assert big.read("big.py") is not None
    assert len(big.read("big.py").lines) <= MAX_SOURCE_BYTES // 40  # type: ignore[union-attr]


def test_make_rule_still_builds_test_metadata() -> None:
    """Phase 7 test helper contract is untouched by Phase 8."""
    rule = make_rule("SEC-TEST-999")
    assert rule.rule_id == "SEC-TEST-999"
    assert rule.analyzer_id == "security"
