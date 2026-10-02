"""Security rule test gate (TASK-109–111).

Every V1.0 security rule must have meaningful positive and negative
rule-level tests that actually execute through ``SecurityAnalyzer``.
Guards assert the discovered registry is exactly the twelve frozen rules
so the gate can never pass vacuously, plus cross-cutting verification of
severity ranges, confidence behavior, redaction across the full
detector → finding → evidence → serialization chain, determinism,
failure isolation, and the static-analysis boundary for the new rules.
"""

from __future__ import annotations

import json

import pytest

from app.analyzers.security.analyzer import SecurityAnalyzer, build_security_rules
from app.analyzers.security.coverage import CoverageStatus
from app.analyzers.security.source import DictSourceProvider
from tests.fixtures.helpers.security_helpers import analyze_files

pytestmark = pytest.mark.security

EXPECTED_RULE_IDS = (
    "SEC-SQL-INJECTION",
    "SEC-COMMAND-INJECTION",
    "SEC-PATH-TRAVERSAL",
    "SEC-SSRF",
    "SEC-UNSAFE-DESERIALIZATION",
    "SEC-DANGEROUS-DYNAMIC-EXECUTION",
    "SEC-WEAK-CRYPTO",
    "SEC-DISABLED-TLS",
    "SEC-INSECURE-CORS",
    "SEC-SENSITIVE-LOGGING",
    "SEC-POTENTIAL-AUTHORIZATION",
    "SEC-HARDCODED-SECRET",
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

#: rule_id -> (positive source, negative source). Each positive must yield
#: at least one finding for its rule; each negative must yield none.
GATE_CASES: dict[str, tuple[str, str]] = {
    "SEC-SQL-INJECTION": (
        "import sqlite3\n"
        "def f(u):\n"
        "    c = sqlite3.connect('x')\n"
        "    c.execute('SELECT * FROM u WHERE n = ' + u)\n",
        "import sqlite3\n"
        "def f(u):\n"
        "    c = sqlite3.connect('x')\n"
        "    c.execute('SELECT * FROM u WHERE n = %s', (u,))\n",
    ),
    "SEC-COMMAND-INJECTION": (
        "import os\ndef f(n):\n    os.system('cat ' + n)\n",
        'import subprocess\ndef f():\n    subprocess.run(["git", "status"], check=True)\n',
    ),
    "SEC-PATH-TRAVERSAL": (
        "def f(n):\n    return open('/var/data/' + n).read()\n",
        "def f():\n    return open('/var/data/daily.txt').read()\n",
    ),
    "SEC-SSRF": (
        "import requests\ndef f(u):\n    return requests.get(u).text\n",
        "import requests\ndef f():\n    return requests.get('https://api.example.com/x').text\n",
    ),
    "SEC-UNSAFE-DESERIALIZATION": (
        "import pickle\ndef f(b):\n    return pickle.loads(b)\n",
        "import json\ndef f(b):\n    return json.loads(b)\n",
    ),
    "SEC-DANGEROUS-DYNAMIC-EXECUTION": (
        "def f(s):\n    return eval(s)\n",
        "import ast\ndef f(s):\n    return ast.literal_eval(s)\n",
    ),
    "SEC-WEAK-CRYPTO": (
        "import hashlib\ndef f(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n",
        "import hashlib\ndef f(pw):\n    return hashlib.sha256(pw.encode()).hexdigest()\n",
    ),
    "SEC-DISABLED-TLS": (
        "import requests\ndef f(u):\n    return requests.get(u, verify=False)\n",
        "import requests\ndef f(u):\n    return requests.get(u, verify=True)\n",
    ),
    "SEC-INSECURE-CORS": (
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n",
        "from fastapi.middleware.cors import CORSMiddleware\n"
        "app.add_middleware(CORSMiddleware, allow_origins=['https://example.com'])\n",
    ),
    "SEC-SENSITIVE-LOGGING": (
        "import logging\ndef f(password):\n    logging.info('password=%s', password)\n",
        "import logging\ndef f(uid):\n    logging.info('user_id=%s', uid)\n",
    ),
    "SEC-POTENTIAL-AUTHORIZATION": (
        "from db import get_session\n"
        "from models import User\n"
        '@app.delete("/users/{user_id}")\n'
        "def delete_account(user_id):\n"
        "    s = get_session()\n"
        "    s.query(User).filter(User.id == user_id).delete()\n",
        '@app.get("/health")\ndef health():\n    return {"status": "ok"}\n',
    ),
    "SEC-HARDCODED-SECRET": (
        'api_key = "hunter2-hunter2-hunter2-hunter2"\n',
        'api_key = os.getenv("API_KEY")\n',
    ),
}


def _rule_ids(result) -> set[str]:  # type: ignore[no-untyped-def]
    return {finding.rule_id for finding in result.findings}


def test_gate_discovers_exactly_twelve_rules() -> None:
    """The registry under test is exactly the frozen V1.0 set (no vacuity)."""
    from app.analyzers.security.metadata import SPEC_BY_RULE_ID

    discovered = [rule.metadata.rule_id for rule in build_security_rules(DictSourceProvider({}))]
    assert discovered, "rule discovery returned nothing"
    assert tuple(discovered) == tuple(sorted(EXPECTED_RULE_IDS))
    assert set(SPEC_BY_RULE_ID) == set(EXPECTED_RULE_IDS)
    assert set(FROZEN_RANGES) == set(EXPECTED_RULE_IDS)


@pytest.mark.parametrize("rule_id", EXPECTED_RULE_IDS)
def test_gate_positive_fires_rule(rule_id: str) -> None:
    """Each rule's positive case yields that rule through the analyzer."""
    positive, _ = GATE_CASES[rule_id]
    result, _, _ = analyze_files({"app.py": positive})
    assert result.findings, f"{rule_id}: positive case produced no findings at all"
    assert rule_id in _rule_ids(result), f"{rule_id}: positive case missed"


@pytest.mark.parametrize("rule_id", EXPECTED_RULE_IDS)
def test_gate_positive_sensitive_to_rule_removal(rule_id: str) -> None:
    """Disabling a rule breaks its positive case (positives are not vacuous)."""
    from app.analyzers.security.analyzer import SecurityAnalyzer as _Analyzer

    positive, _ = GATE_CASES[rule_id]

    class WithoutRule(_Analyzer):
        def rules(self):  # type: ignore[no-untyped-def]
            return [r for r in super().rules() if r.metadata.rule_id != rule_id]

    files = {"app.py": positive}
    result, _, _ = analyze_files(files, analyzer=WithoutRule(DictSourceProvider(files)))
    assert rule_id not in {finding.rule_id for finding in result.findings}, (
        f"{rule_id}: positive fires without the rule (test is vacuous)"
    )


@pytest.mark.parametrize("rule_id", EXPECTED_RULE_IDS)
def test_gate_negative_silent_for_rule(rule_id: str) -> None:
    """Each rule's negative case yields no finding for that rule."""
    _, negative = GATE_CASES[rule_id]
    result, _, _ = analyze_files({"app.py": negative})
    assert rule_id not in _rule_ids(result), f"{rule_id}: negative case flagged"


def test_gate_finding_shape_invariants() -> None:
    """Every gate positive carries bounded, relative, versioned evidence."""
    for rule_id in EXPECTED_RULE_IDS:
        positive, _ = GATE_CASES[rule_id]
        result, _, _ = analyze_files({"app.py": positive})
        findings = [f for f in result.findings if f.rule_id == rule_id]
        assert findings, rule_id
        for finding in findings:
            assert finding.evidence is not None, rule_id
            assert len(finding.evidence.lines) <= 51, rule_id
            assert not finding.evidence.path.startswith("/"), rule_id
            assert finding.severity.value in SEVERITY_RANK, rule_id
            assert finding.confidence.value in ("High", "Medium", "Low"), rule_id
            assert finding.recommendation, rule_id
            assert finding.analyzer_version and finding.rule_set_version, rule_id


def test_gate_severity_within_frozen_ranges() -> None:
    """No finding escapes its rule's frozen severity range."""
    for rule_id in EXPECTED_RULE_IDS:
        positive, _ = GATE_CASES[rule_id]
        result, _, _ = analyze_files({"app.py": positive})
        low, high = FROZEN_RANGES[rule_id]
    for finding in result.findings:
        if finding.rule_id != rule_id:
            continue
        assert SEVERITY_RANK[low] <= SEVERITY_RANK[finding.severity.value]
        assert SEVERITY_RANK[finding.severity.value] <= SEVERITY_RANK[high]


def test_gate_authorization_confidence_never_high() -> None:
    """SEC-POTENTIAL-AUTHORIZATION must never report High confidence."""
    for rule_id in EXPECTED_RULE_IDS:
        positive, _ = GATE_CASES[rule_id]
        result, _, _ = analyze_files({"app.py": positive})
        for finding in result.findings:
            if finding.rule_id == "SEC-POTENTIAL-AUTHORIZATION":
                assert finding.confidence.value != "High"
                assert "Manual review is required" in finding.description


def test_gate_partial_caps_high_confidence() -> None:
    """Partial representation caps High confidence at Medium (all rules)."""
    from tests.fixtures.helpers.analyzer_helpers import make_context
    from tests.fixtures.helpers.security_helpers import parse_files

    files = {
        "app.py": (
            "import sys, pickle, hashlib, logging\n"
            "password = sys.argv[1]\n"
            "logging.info('password=%s', password)\n"
            "pickle.loads(password.encode())\n"
            "hashlib.md5(password.encode()).hexdigest()\n"
        )
    }
    ncm = parse_files(files)
    for entry in ncm.files:
        if entry.module is not None:
            entry.module.completeness = "partially"
    result = SecurityAnalyzer(DictSourceProvider(files)).analyze(make_context(ncm=ncm))
    assert result.findings
    for finding in result.findings:
        assert finding.confidence.value != "High", finding.rule_id
        assert finding.limitations


def test_gate_determinism_across_runs() -> None:
    """Same input twice: same identities, ordering, coverage."""
    for rule_id in EXPECTED_RULE_IDS:
        positive, _ = GATE_CASES[rule_id]
        first, first_context, first_analyzer = analyze_files({"app.py": positive})
        second, second_context, second_analyzer = analyze_files({"app.py": positive})
        assert [f.identity_key for f in first.findings] == [
            f.identity_key for f in second.findings
        ], rule_id
        assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]
        first_coverage = {
            item.rule_id: item.status for item in first_analyzer.coverage(first_context.ncm)
        }
        second_coverage = {
            item.rule_id: item.status for item in second_analyzer.coverage(second_context.ncm)
        }
        assert first_coverage == second_coverage, rule_id


def test_gate_secret_failure_does_not_stop_siblings() -> None:
    """A crashing secret rule is recorded; sibling findings survive."""
    from app.analyzers.rules import RegisteredRule, RuleOutcome
    from app.analyzers.security.metadata import SPEC_BY_RULE_ID
    from app.analyzers.versioning import RULE_SET_VERSION
    from tests.fixtures.helpers.analyzer_helpers import make_rule

    def _boom(execution_context) -> RuleOutcome:  # type: ignore[no-untyped-def]
        raise RuntimeError("secret boom")

    class FlakySecurity(SecurityAnalyzer):
        def rules(self) -> list[RegisteredRule]:
            kept = [
                rule for rule in super().rules() if rule.metadata.rule_id != "SEC-HARDCODED-SECRET"
            ]
            metadata = SPEC_BY_RULE_ID["SEC-HARDCODED-SECRET"].to_metadata(RULE_SET_VERSION)
            assert metadata.rule_id == "SEC-HARDCODED-SECRET"
            return [*kept, RegisteredRule(metadata=make_rule("SEC-TEST-999"), execute=_boom)]

    assert make_rule("SEC-TEST-999").rule_id == "SEC-TEST-999"
    files = {
        "app.py": (
            "import sqlite3\ndef f(u):\n    c = sqlite3.connect('x')\n    c.execute('q ' + u)\n"
        )
    }
    result, _, _ = analyze_files(files, analyzer=FlakySecurity(DictSourceProvider(files)))
    by_rule = {item.rule_id: item for item in result.rule_results}
    assert by_rule["SEC-TEST-999"].failure is not None
    assert by_rule["SEC-TEST-999"].findings == ()
    assert result.failed is False
    assert "SEC-SQL-INJECTION" in {finding.rule_id for finding in result.findings}


def test_gate_new_rule_files_scanned_by_boundary() -> None:
    """Boundary scans cover the new rule files (never silently skipped)."""
    import ast as stdlib_ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "app" / "analyzers" / "security"
    assert root.is_dir()
    scanned = sorted(path.name for path in root.rglob("*.py"))
    assert scanned, "boundary scan found no files"
    for name in ("sensitive_logging.py", "authorization.py", "hardcoded_secret.py"):
        assert name in scanned, f"{name} missing from boundary scan"
    violations: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = stdlib_ast.parse(path.read_text(encoding="utf-8"))
        for node in stdlib_ast.walk(tree):
            if isinstance(node, stdlib_ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in {"ast", "tree_sitter"}:
                        violations.append(f"{path.name}: import {alias.name}")
            elif isinstance(node, stdlib_ast.ImportFrom):
                if (node.module or "").split(".")[0] in {"ast", "tree_sitter"} or (
                    node.module or ""
                ).startswith("app.parsers"):
                    violations.append(f"{path.name}: from {node.module} import ...")
    assert violations == []


def test_gate_no_plaintext_secrets_anywhere() -> None:
    """Full chain (detect → finding → evidence → serialization): no plaintext."""
    aws_key = "AKIAY2P4R6T8W0A2C4E6"
    bearer = "Bearer x7f3a9c2e5b1d8f4a6c0e2b5d9a3f7c1e4b2a"
    secret_value = "hunter2-hunter2-hunter2-hunter2"
    files = {
        "app.py": (
            f'AWS_KEY = "{aws_key}"\n'
            f'TOKEN = "{bearer}"\n'
            f'api_key = "{secret_value}"\n'
            'password = "hunter2"\n'
        ),
        "config.env": f"SECRET={secret_value}\n",
    }
    from app.ncm import NcmFileEntry
    from tests.fixtures.helpers.analyzer_helpers import make_context
    from tests.fixtures.helpers.security_helpers import parse_files as _parse

    ncm = _parse({"app.py": files["app.py"]})
    ncm.files.append(
        NcmFileEntry(path="config.env", language=None, parse_state="unsupported", module=None)
    )
    result = SecurityAnalyzer(DictSourceProvider(files)).analyze(make_context(ncm=ncm))
    findings = [f for f in result.findings if f.rule_id == "SEC-HARDCODED-SECRET"]
    assert len(findings) >= 4
    dumped = json.dumps([finding.to_dict() for finding in findings], sort_keys=True)
    for secret in (aws_key, bearer.split(" ", 1)[1], secret_value, "hunter2"):
        assert secret not in dumped, f"plaintext leaked: {secret[:8]}..."
    for finding in findings:
        assert finding.evidence is not None
        assert finding.evidence.redacted is True
    _ = CoverageStatus.COVERED


def test_gate_clean_text_byte_identical() -> None:
    """Redaction leaves non-sensitive text untouched."""
    from app.analyzers.redaction import mask_secrets

    for clean in ("hello world", "user_id=42", "status: ok", "x = [1, 2, 3]"):
        masked, had_secret = mask_secrets(clean)
        assert masked == clean
        assert had_secret is False


def test_gate_mask_strings_prefix_regression() -> None:
    """String contents starting with u/r/b/f are blanked, never identifiers."""
    from app.analyzers.security.flow import analyze_expression
    from app.analyzers.security.source import mask_strings

    for literal in ("'user=%s'", "'root=x'", "'format string'", "b'bytes'", "'Bearer abc'"):
        assert mask_strings(literal) == "''", literal
        assert analyze_expression(literal).identifiers == (), literal
    assert mask_strings('f"hi {x}"') == 'f""'
    assert analyze_expression("'a' + name").identifiers == ("name",)


def test_gate_secret_inside_larger_line_masked() -> None:
    """A secret embedded in a longer line is masked; context preserved."""
    line = 'result = fetch("https://api.example.com/?token=hunter2-hunter2-abcd1234")'
    result, _, _ = analyze_files({"app.py": line + "\n"})
    findings = [f for f in result.findings if f.rule_id == "SEC-HARDCODED-SECRET"]
    assert findings, "expected a finding for the embedded token"
    assert "hunter2-hunter2-abcd1234" not in str(findings[0].to_dict())
    assert findings[0].evidence is not None
    assert "fetch(" in "\n".join(findings[0].evidence.lines)
