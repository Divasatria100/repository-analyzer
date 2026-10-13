"""Architecture boundary tests (TASK-123 gate, Section 18).

The architecture analyzer consumes NCM and never reaches past it: no
``ast``/``tree_sitter`` imports, no ``app.parsers`` modules, no subprocesses,
no network clients, no target imports. No architecture score exists.
"""

import ast
from pathlib import Path

import pytest

from tests.fixtures.helpers.architecture_helpers import analyze_arch

ARCHITECTURE_ROOT = Path(__file__).resolve().parents[2] / "app" / "analyzers" / "architecture"

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


def _architecture_files() -> list[Path]:
    return sorted(ARCHITECTURE_ROOT.rglob("*.py"))


def test_no_parser_or_execution_imports() -> None:
    """Fail if any architecture module reaches past NCM or into execution."""
    violations: list[str] = []
    for path in _architecture_files():
        for name in _imported_modules(path):
            top = name.split(".")[0]
            if top in FORBIDDEN_TOP_LEVEL or name in FORBIDDEN_PARSERS_SUBMODULES:
                violations.append(f"{path.name}: {name}")
    assert violations == []


def test_no_execution_or_network_calls() -> None:
    """Fail on eval/exec/subprocess/socket-style calls in architecture code."""
    violations: list[str] = []
    for path in _architecture_files():
        for name in _called_names(path):
            if name in FORBIDDEN_CALLS:
                violations.append(f"{path.name}: {name}()")
    assert violations == []


def test_analyzer_operates_from_ncm_without_source() -> None:
    """With no source provider, graph rules still run from NCM alone."""
    from app.analyzers.architecture.analyzer import ArchitectureAnalyzer

    result, _, _ = analyze_arch(
        {"a.py": "import b\n", "b.py": "import a\n"},
        analyzer=ArchitectureAnalyzer(None),
    )
    assert {finding.rule_id for finding in result.findings} == {"ARCH-CIRCULAR-DEPENDENCY"}


def test_no_target_code_execution_tripwire(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tripwire: subprocess spawn during analysis fails loudly."""
    import subprocess

    calls: list[object] = []

    def _forbidden(*args: object, **kwargs: object) -> object:
        calls.append(args)
        raise AssertionError("target execution is forbidden")

    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    result, _, _ = analyze_arch({"a.py": "import b\n", "b.py": "X = 1\n"})
    assert calls == []
    assert result.rule_results


def test_no_network_access_tripwire(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tripwire: non-loopback socket use during analysis fails loudly."""
    import socket

    real_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: object) -> None:
        host = address[0] if isinstance(address, tuple) else str(address)
        raise AssertionError(f"network access is forbidden: {host}")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    result, _, _ = analyze_arch({"a.py": "import b\n", "b.py": "X = 1\n"})
    assert result.rule_results
    _ = real_connect


def test_no_dynamic_target_imports() -> None:
    """Analysis adds no target-named modules to sys.modules."""
    import sys

    before = set(sys.modules)
    analyze_arch({"victim_module.py": "X = 1\n"})
    added = {name.split(".")[0] for name in set(sys.modules) - before}
    assert "victim_module" not in added
