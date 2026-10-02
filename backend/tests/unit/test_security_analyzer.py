"""Security analyzer pipeline tests (TASK-094).

Proves the ``security`` analyzer runs registered rules through the
existing Phase 6 framework: stable identity, registry discovery (no
hard-coded chain), per-rule isolation, deterministic output, dedup, and
security-only scope.
"""

import pytest

from app.analyzers.rules import RegisteredRule, RuleOutcome
from app.analyzers.security.analyzer import (
    SECURITY_ANALYZER_VERSION,
    SecurityAnalyzer,
    build_security_rules,
)
from app.analyzers.security.source import DictSourceProvider
from tests.fixtures.helpers.analyzer_helpers import make_rule
from tests.fixtures.helpers.security_helpers import analyze_files

VULN_SQL = (
    "import sqlite3\n"
    "def find_user(username):\n"
    "    conn = sqlite3.connect('example.db')\n"
    "    query = f\"SELECT * FROM users WHERE name = '{username}'\"\n"
    "    return conn.execute(query).fetchall()\n"
)

VULN_CMD = "import subprocess\ndef ping(host):\n    subprocess.run('ping ' + host, shell=True)\n"


def test_analyzer_identity_is_stable() -> None:
    """The security analyzer carries the frozen ``security`` identity."""
    analyzer = SecurityAnalyzer(DictSourceProvider({}))
    assert analyzer.id == "security"
    assert analyzer.name
    assert analyzer.version == SECURITY_ANALYZER_VERSION


def test_rules_come_from_registry_in_deterministic_order() -> None:
    """Twelve V1.0 rules, sorted by rule ID (no hard-coded chain)."""
    rules = build_security_rules(DictSourceProvider({}))
    assert [rule.metadata.rule_id for rule in rules] == [
        "SEC-COMMAND-INJECTION",
        "SEC-DANGEROUS-DYNAMIC-EXECUTION",
        "SEC-DISABLED-TLS",
        "SEC-HARDCODED-SECRET",
        "SEC-INSECURE-CORS",
        "SEC-PATH-TRAVERSAL",
        "SEC-POTENTIAL-AUTHORIZATION",
        "SEC-SENSITIVE-LOGGING",
        "SEC-SQL-INJECTION",
        "SEC-SSRF",
        "SEC-UNSAFE-DESERIALIZATION",
        "SEC-WEAK-CRYPTO",
    ]
    assert all(rule.metadata.analyzer_id == "security" for rule in rules)


def test_analyzer_runs_only_security_rules() -> None:
    """No dependency/architecture/code-structure rule ever executes here."""
    result, _, _ = analyze_files({"app.py": VULN_SQL})
    assert result.rule_results
    assert {item.rule_id for item in result.rule_results} == {
        "SEC-COMMAND-INJECTION",
        "SEC-DANGEROUS-DYNAMIC-EXECUTION",
        "SEC-DISABLED-TLS",
        "SEC-HARDCODED-SECRET",
        "SEC-INSECURE-CORS",
        "SEC-PATH-TRAVERSAL",
        "SEC-POTENTIAL-AUTHORIZATION",
        "SEC-SENSITIVE-LOGGING",
        "SEC-SQL-INJECTION",
        "SEC-SSRF",
        "SEC-UNSAFE-DESERIALIZATION",
        "SEC-WEAK-CRYPTO",
    }
    assert all(finding.category == "security" for finding in result.findings)


def test_rule_failure_does_not_stop_siblings() -> None:
    """A crashing rule is recorded; sibling findings are preserved."""

    def _boom(execution_context) -> RuleOutcome:  # type: ignore[no-untyped-def]
        raise RuntimeError("rule boom")

    class FlakySecurity(SecurityAnalyzer):
        def rules(self) -> list[RegisteredRule]:
            return [
                *super().rules(),
                RegisteredRule(metadata=make_rule("SEC-TEST-999"), execute=_boom),
            ]

    files = {"app.py": VULN_SQL + VULN_CMD}
    result, _, _ = analyze_files(files, analyzer=FlakySecurity(DictSourceProvider(files)))
    by_rule = {item.rule_id: item for item in result.rule_results}
    assert by_rule["SEC-TEST-999"].failure is not None
    assert by_rule["SEC-TEST-999"].findings == ()
    assert result.failed is False
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "SEC-SQL-INJECTION" in rule_ids
    assert "SEC-COMMAND-INJECTION" in rule_ids


def test_failed_rule_is_never_clean() -> None:
    """A failed rule carries a failure record, not an empty clean result."""

    def _boom(execution_context) -> RuleOutcome:  # type: ignore[no-untyped-def]
        raise RuntimeError("rule boom")

    class FlakySecurity(SecurityAnalyzer):
        def rules(self) -> list[RegisteredRule]:
            return [RegisteredRule(metadata=make_rule("SEC-TEST-999"), execute=_boom)]

    result, _, _ = analyze_files(
        {"app.py": VULN_SQL}, analyzer=FlakySecurity(DictSourceProvider({}))
    )
    assert len(result.rule_results) == 1
    assert result.rule_results[0].failure is not None
    assert result.rule_results[0].findings == ()


def test_output_is_deterministic() -> None:
    """Two runs over the same snapshot agree on everything observable."""
    files = {"app.py": VULN_SQL + VULN_CMD}
    first, _, _ = analyze_files(files)
    second, _, _ = analyze_files(files)
    assert [f.identity_key for f in first.findings] == [f.identity_key for f in second.findings]
    assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]


def test_findings_have_no_duplicate_identities() -> None:
    """The same logical issue is never reported twice."""
    files = {
        "a.py": VULN_SQL,
        "b.py": VULN_SQL.replace("example.db", "other.db"),
    }
    result, _, _ = analyze_files(files)
    keys = [finding.identity_key for finding in result.findings]
    assert len(keys) == len(set(keys))
    ordered = [
        (
            finding.location.file_path,
            finding.location.start_line,
            finding.location.start_column,
            finding.rule_id,
        )
        for finding in result.findings
    ]
    assert ordered == sorted(ordered)


def test_findings_carry_versions_and_recommendations() -> None:
    """Every finding traces to its versions and advises review."""
    result, _, _ = analyze_files({"app.py": VULN_SQL})
    assert result.findings
    for finding in result.findings:
        assert finding.analyzer_version
        assert finding.rule_set_version == "1.0"
        assert finding.recommendation
        assert "potential" in finding.description.lower() or "Potential" in finding.title


@pytest.mark.security
def test_no_parser_imports_in_security_package() -> None:
    """The Phase 6 dependency direction holds for the new security code."""
    import ast as stdlib_ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "app" / "analyzers" / "security"
    assert root.is_dir()
    forbidden = {
        "app.parsers.base",
        "app.parsers.pipeline",
        "app.parsers.python_ast",
        "app.parsers.registry",
        "app.parsers.runner",
        "app.parsers.tree_sitter",
        "app.parsers.worker",
    }
    violations: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = stdlib_ast.parse(path.read_text(encoding="utf-8"))
        for node in stdlib_ast.walk(tree):
            if isinstance(node, stdlib_ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, stdlib_ast.ImportFrom):
                names = [node.module] if node.module else []
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if top in {"ast", "tree_sitter"} or name in forbidden:
                    violations.append(f"{path.name}: {name}")
    assert violations == []
