"""Code-structure boundary tests (Phase 10, Section 18 analogue).

The analyzer consumes NCM and bounded source lines only: no ``ast`` /
``tree_sitter`` / ``app.parsers.*`` imports, no subprocesses, no network,
no target imports, no second parsing pass. No aggregate score exists.
"""

import ast
from pathlib import Path

import pytest

from tests.fixtures.helpers.code_structure_helpers import analyze_code

CODE_ROOT = Path(__file__).resolve().parents[2] / "app" / "analyzers" / "code_structure"

FORBIDDEN_TOP_LEVEL = {"ast", "tree_sitter", "subprocess", "socket", "httpx", "requests"}
FORBIDDEN_PARSERS_SUBMODULES = frozenset(
    {
        "app.parsers.base",
        "app.parsers.pipeline",
        "app.parsers.python_ast",
        "app.parsers.registry",
        "app.parsers.runner",
        "app.parsers.tree_sitter",
        "app.parsers.worker",
    }
)
FORBIDDEN_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "import_module",
    "run",
    "call",
    "Popen",
    "check_call",
    "check_output",
    "system",
    "popen",
    "connect",
    "urlopen",
}


def _imported_modules(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.append(node.module)
    return names


def _called_names(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.append(func.id)
            elif isinstance(func, ast.Attribute):
                names.append(func.attr)
    return names


def test_no_parser_or_execution_imports() -> None:
    """Fail if any code-structure module reaches past NCM or into execution."""
    violations: list[str] = []
    for path in sorted(CODE_ROOT.rglob("*.py")):
        for name in _imported_modules(path):
            top = name.split(".")[0]
            if top in FORBIDDEN_TOP_LEVEL or name in FORBIDDEN_PARSERS_SUBMODULES:
                violations.append(f"{path.name}: {name}")
    assert violations == []


def test_no_execution_or_network_calls() -> None:
    """Fail on eval/exec/subprocess/socket-style calls in code-structure code."""
    violations: list[str] = []
    for path in sorted(CODE_ROOT.rglob("*.py")):
        for name in _called_names(path):
            if name in FORBIDDEN_CALLS:
                violations.append(f"{path.name}: {name}()")
    assert violations == []


def test_no_tokenize_abuse_tokenizer_stays_lexical() -> None:
    """The tokenizer module must not build syntax trees or import parsers."""
    text = (CODE_ROOT / "tokens.py").read_text(encoding="utf-8")
    assert "tokenize" in text
    assert "ast." not in text
    tree = ast.parse(text, filename="tokens.py")
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert imported <= {"__future__", "io", "keyword", "tokenize"}


def test_analyzer_operates_from_ncm_without_source() -> None:
    """Measurement rules run from NCM alone; duplicates stay unevaluated."""
    from app.analyzers.code_structure.analyzer import CodeStructureAnalyzer
    from tests.fixtures.helpers.code_structure_helpers import decision_body, rule_result

    result, _, _ = analyze_code(
        {"m.py": f"def work(x):\n{decision_body(11)}"},
        analyzer=CodeStructureAnalyzer(None),
    )
    assert len(rule_result(result, "CODE-HIGH-COMPLEXITY").findings) == 1
    outcome = rule_result(result, "CODE-DUPLICATE-CANDIDATE")
    assert outcome.findings == ()
    assert any("not evaluated" in item.reason for item in outcome.limitations)


def test_no_target_code_execution_tripwire(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tripwire: subprocess spawn during analysis fails loudly."""
    import subprocess

    calls: list[object] = []

    def _forbidden(*args: object, **kwargs: object) -> object:
        calls.append(args)
        raise AssertionError("target execution is forbidden")

    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    result, _, _ = analyze_code({"m.py": "def f():\n    pass\n"})
    assert calls == []
    assert result.rule_results


def test_no_network_access_tripwire() -> None:
    """The analyzer holds no client capable of network access."""
    from app.analyzers.code_structure.analyzer import CodeStructureAnalyzer

    analyzer = CodeStructureAnalyzer(None)
    assert not any("client" in name.lower() for name in vars(analyzer))
    result, _, _ = analyze_code({"m.py": "def f():\n    pass\n"})
    assert result.rule_results


def test_no_dynamic_target_imports() -> None:
    """Analysis adds no target-named modules to sys.modules."""
    import sys

    before = set(sys.modules)
    analyze_code({"victim_module.py": "X = 1\n"})
    added = {name.split(".")[0] for name in set(sys.modules) - before}
    assert "victim_module" not in added


def test_no_second_parse_of_source() -> None:
    """Source lines are tokenized as data; no syntax tree is ever built."""
    import app.analyzers.code_structure.tokens as tokens_module

    source = "def f():\n    x = 1\n"
    assert tokens_module.normalize_body_tokens(source, local_names=frozenset({"x"})) is not None
    assert not hasattr(tokens_module, "parse")
    assert not hasattr(tokens_module, "walk")
