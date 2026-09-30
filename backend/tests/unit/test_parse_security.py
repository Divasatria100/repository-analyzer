"""Parse-path security tests: no execution, no shell, no network (TASK-071).

Proves the parser boundary treats repository content as inert data:
adapters never import repository modules, the worker spawns through argv
lists only, hostile filenames cannot reach a shell, and no non-loopback
network access occurs (global tripwire in conftest).
"""

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from app.parsers.base import ParserInput
from app.parsers.python_ast import PythonAstAdapter
from app.parsers.result import ParseState
from app.parsers.runner import run_adapter
from app.parsers.tree_sitter import TreeSitterAdapter
from tests.fixtures.helpers.canary import assert_canary_absent, fixture_contains_canary_payload
from tests.fixtures.helpers.paths import read_fixture_bytes

pytestmark = pytest.mark.security


def test_worker_spawn_uses_argv_without_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    """The single spawned process is an argv list; shell is never enabled."""
    seen_args: list[object] = []
    seen_kwargs: list[object] = []
    real_popen = subprocess.Popen

    def recording_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        seen_args.append(args)
        seen_kwargs.append(kwargs)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", recording_popen)
    result = run_adapter("python-ast", "python", "a.py", b"x = 1\n", timeout_s=30.0)
    assert result.state == ParseState.PARSED
    assert len(seen_args) == 1
    argv = seen_args[0]
    options = seen_kwargs[0]
    assert isinstance(argv, tuple) and isinstance(argv[0], list)
    assert argv[0][0] == sys.executable
    assert isinstance(options, dict) and options.get("shell", False) is False


def test_hostile_filename_cannot_reach_shell() -> None:
    """Metacharacters in repository paths stay inert inside argv lists."""
    result = run_adapter("python-ast", "python", "a;b$(x)`y`.py", b"x = 1\n", timeout_s=30.0)
    assert result.state == ParseState.PARSED
    assert result.ncm is not None
    assert result.ncm.module.file_path == "a;b$(x)`y`.py"


def test_canary_never_executes_in_adapters() -> None:
    """Canary bytes parsed by both adapters produce no side effects."""
    source = read_fixture_bytes("security", "execution_canary.py")
    assert fixture_contains_canary_payload(source.decode("utf-8"))
    for adapter in (PythonAstAdapter(), TreeSitterAdapter()):
        result = adapter.parse(ParserInput("canary_check.py", "python", source, 30.0, 1_000_000))
        assert result.state == ParseState.PARSED
    assert_canary_absent()
    assert "canary_check" not in sys.modules
    assert "execution_canary" not in sys.modules


def test_no_package_manager_or_build_invocation(tmp_path: Path) -> None:
    """Manifest content is data: invalid Python fails safely, nothing runs."""
    root = tmp_path / "ws"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    source = (root / "requirements.txt").read_bytes()
    result = run_adapter("python-ast", "python", "requirements.txt", source, timeout_s=30.0)
    assert result.state == ParseState.FAILED
    assert (tmp_path / "ws" / "pip-log.txt").exists() is False
    assert_canary_absent()
