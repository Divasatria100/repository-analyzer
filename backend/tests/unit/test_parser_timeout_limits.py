"""Timeout, input-limit, and runner mechanism tests (TASK-068).

The timeout test exercises the real kill path: a tiny deadline against a
large input guarantees the worker cannot finish in time, proving an
overdue parser is terminated rather than left running.
"""

import sys

import pytest

from app.ncm import ParseState
from app.parsers.runner import backend_root, build_worker_command, run_adapter

pytestmark = pytest.mark.security


def test_worker_command_is_argv_list() -> None:
    command = build_worker_command("python-ast", "python", "pkg/m.py")
    assert command[0] == sys.executable
    assert command[1:5] == ["-m", "app.parsers.worker", "python-ast", "python"]
    assert command[5] == "pkg/m.py"
    assert all(isinstance(part, str) for part in command)
    assert backend_root().name == "backend"
    assert (backend_root() / "app" / "parsers" / "worker.py").is_file()


def test_timeout_kills_overdue_worker() -> None:
    source = b"\n".join(b"def f%d():\n    return %d" % (i, i) for i in range(4000))
    assert len(source) > 100_000
    result = run_adapter("python-ast", "python", "big.py", source, timeout_s=0.05)
    assert result.state == ParseState.FAILED
    assert result.ncm is None
    assert any(d.code == "timeout" for d in result.diagnostics)
    assert "0.05s" in result.diagnostics[0].message


def test_unknown_adapter_is_infrastructure_failure() -> None:
    result = run_adapter("nope", "python", "a.py", b"x = 1\n", timeout_s=30.0)
    assert result.state == ParseState.FAILED
    assert any(d.code == "infrastructure" for d in result.diagnostics)


def test_runner_roundtrip_preserves_ncm() -> None:
    source = b"import os\n\ndef f(a, b=2):\n    return g(a)\n"
    result = run_adapter("python-ast", "python", "pkg/m.py", source, timeout_s=30.0)
    assert result.state == ParseState.PARSED
    assert result.ncm is not None
    assert result.ncm.module.file_path == "pkg/m.py"
    assert result.ncm.functions[0].qualified_name == "m.f"
    assert result.ncm.functions[0].location.file_path == "pkg/m.py"


def test_timeout_value_comes_from_config() -> None:
    from app.core.config import load_settings

    settings = load_settings()
    assert settings.operational.parse_file_timeout_s == 30
    assert settings.operational.file_max_size_bytes == 1_048_576
