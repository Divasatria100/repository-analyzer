"""Security non-execution boundary tests (Phase 7 safety gate).

The analyzer itself must remain static: it recognizes dangerous
patterns (``subprocess.run``, ``os.system``) as *source-code text* in
the analyzed repository, but it must never call them — no subprocess
spawns, no shell execution, no network access, no dynamic imports of
analyzed code, no package installation.
"""

import ast as stdlib_ast
from pathlib import Path

import pytest

from app.analyzers.security.analyzer import SecurityAnalyzer
from tests.fixtures.helpers.canary import assert_canary_absent, fixture_contains_canary_payload
from tests.fixtures.helpers.paths import read_fixture_text
from tests.fixtures.helpers.security_helpers import analyze_files

pytestmark = pytest.mark.security

SECURITY_ROOT = Path(__file__).resolve().parents[2] / "app" / "analyzers" / "security"

#: Imports that would mean the analyzer executes code or touches a network.
#: ``pathlib`` is deliberately absent: path arithmetic is not execution.
FORBIDDEN_IMPORTS = frozenset(
    {
        "subprocess",
        "socket",
        "urllib.request",
        "urllib",
        "http.client",
        "http",
        "httpx",
        "requests",
        "os",  # checked separately: only os.lstat-style reading is allowed
        "shutil",
        "importlib",
        "runpy",
        "pkgutil",
        "pickle",
    }
)

#: Bare-name calls that would mean the analyzer executes analyzed content.
FORBIDDEN_BARE_CALLS = frozenset({"eval", "exec", "compile", "__import__"})

#: Receiver-qualified calls that would mean execution or network access.
FORBIDDEN_RECEIVERS = frozenset({"os", "subprocess", "socket", "requests", "httpx", "urllib"})
FORBIDDEN_METHODS = frozenset(
    {
        "system",
        "popen",
        "run",
        "call",
        "Popen",
        "check_call",
        "check_output",
        "connect",
        "send",
        "recv",
        "urlopen",
        "get",
        "post",
        "request",
    }
)


def _code_nodes(path: Path) -> tuple[list[str], list[str], list[str]]:
    tree = stdlib_ast.parse(path.read_text(encoding="utf-8"))
    imports: list[str] = []
    bare_calls: list[str] = []
    qualified_calls: list[str] = []
    for node in stdlib_ast.walk(tree):
        if isinstance(node, stdlib_ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, stdlib_ast.ImportFrom):
            if node.module:
                imports.append(node.module)
        elif isinstance(node, stdlib_ast.Call):
            func = node.func
            if isinstance(func, stdlib_ast.Name):
                bare_calls.append(func.id)
            elif isinstance(func, stdlib_ast.Attribute) and isinstance(func.value, stdlib_ast.Name):
                qualified_calls.append(f"{func.value.id}.{func.attr}")
    return imports, bare_calls, qualified_calls


def test_no_execution_or_network_imports_in_security_package() -> None:
    """Security code reads files as data; it never spawns or connects."""
    violations: list[str] = []
    for path in sorted(SECURITY_ROOT.rglob("*.py")):
        imports, _, _ = _code_nodes(path)
        for name in imports:
            top = name.split(".")[0]
            if name in FORBIDDEN_IMPORTS or top in FORBIDDEN_IMPORTS:
                if top == "os" and path.name == "source.py":
                    continue  # bounded lstat-guarded reads only (no exec/spawn)
                violations.append(f"{path.name}: import {name}")
    assert violations == []


def test_no_execution_calls_in_security_package() -> None:
    """Recognizing ``os.system`` as text differs from calling ``system()``."""
    violations: list[str] = []
    for path in sorted(SECURITY_ROOT.rglob("*.py")):
        _, bare_calls, qualified_calls = _code_nodes(path)
        for name in bare_calls:
            if name in FORBIDDEN_BARE_CALLS:
                violations.append(f"{path.name}: call {name}()")
        for dotted in qualified_calls:
            receiver, _, method = dotted.partition(".")
            if receiver in FORBIDDEN_RECEIVERS and method in FORBIDDEN_METHODS:
                violations.append(f"{path.name}: call {dotted}()")
    assert violations == []


def test_no_shell_markers_in_security_package() -> None:
    """The analyzer never enables shell execution (substring scan)."""
    forbidden = ("shell=True", "shell = True")
    violations = [
        f"{path.name}"
        for path in sorted(SECURITY_ROOT.rglob("*.py"))
        for marker in forbidden
        if marker in path.read_text(encoding="utf-8")
    ]
    assert violations == []


def test_canary_flows_through_security_pipeline_without_execution() -> None:
    """Canary bytes: parse → NCM → security analyzer → no side effects."""
    source = read_fixture_text("security", "execution_canary.py")
    assert fixture_contains_canary_payload(source)
    result, _, _ = analyze_files({"canary_check.py": source})
    assert isinstance(result.findings, tuple)
    assert_canary_absent()


def test_security_analysis_opens_no_network() -> None:
    """The global tripwire holds during security analysis (explicit proof)."""
    import socket

    result, _, _ = analyze_files(
        {"app.py": ("import requests\ndef fetch(url):\n    return requests.get(url).text\n")}
    )
    assert result.findings
    with pytest.raises(RuntimeError, match="External network blocked"):
        socket.socket().connect(("example.test", 443))


def test_analyzed_modules_are_never_imported() -> None:
    """Analyzed source never enters sys.modules through the analyzer."""
    import sys

    files = {"injected_app.py": ("import os\ndef run(name):\n    os.system('echo ' + name)\n")}
    result, _, _ = analyze_files(files)
    assert result.findings
    assert "injected_app" not in sys.modules


def test_workspace_provider_reads_without_executing(tmp_path: Path) -> None:
    """Workspace-backed source access treats repository files as data."""
    from app.analyzers.security.source import WorkspaceSourceProvider
    from app.repository.workspace import WorkspaceManager

    root = tmp_path / "ws"
    root.mkdir()
    (root / "app.py").write_text(
        "import subprocess\ndef f(x):\n    subprocess.run(x, shell=True)\n",
        encoding="utf-8",
    )
    manager = WorkspaceManager(tmp_path / "roots")
    provider = WorkspaceSourceProvider(manager, root)
    source = provider.read("app.py")
    assert source is not None
    assert len(source.lines) == 3
    assert provider.read("../outside.py") is None
    assert provider.read("missing.py") is None
    analyzer = SecurityAnalyzer(provider)
    from tests.fixtures.helpers.analyzer_helpers import make_context
    from tests.fixtures.helpers.security_helpers import parse_files

    ncm = parse_files({"app.py": (root / "app.py").read_text()})
    result = analyzer.analyze(make_context(ncm=ncm))
    assert any(f.rule_id == "SEC-COMMAND-INJECTION" for f in result.findings)
    assert_canary_absent()
