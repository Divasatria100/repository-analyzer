"""Subprocess parse runner: real per-file isolation (TASK-068).

Each file parses in a fresh worker process (``python -m
app.parsers.worker``) with source bytes on stdin and one JSON line on
stdout. The parent enforces the configured per-file timeout by killing an
overdue worker — a pathological file cannot block the analysis, and no
parser continues in the background.

No shell, argv list only, DEVNULL stderr, minimal environment. Timeouts,
crashes, and malformed worker output become ``failed`` results with
structured diagnostics (never clean, never partial, never source text).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from app.ncm import Diagnostic, ParseResult, ParseState


def backend_root() -> Path:
    """Backend directory owning the ``app`` package (worker cwd)."""
    return Path(__file__).resolve().parents[2]


def build_worker_command(adapter_name: str, language: str, relative_path: str) -> list[str]:
    """Argv for one isolated parse (list only — shell is never used)."""
    return [sys.executable, "-m", "app.parsers.worker", adapter_name, language, relative_path]


def _worker_env() -> dict[str, str]:
    env: dict[str, str] = {
        "PYTHONUTF8": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    for key in ("PATH", "SYSTEMROOT", "TEMP", "TMP"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


def run_adapter(
    adapter_name: str,
    language: str,
    relative_path: str,
    source: bytes,
    timeout_s: float,
) -> ParseResult:
    """Parse bytes in an isolated worker with an enforced timeout."""
    started = time.perf_counter()
    try:
        proc = subprocess.Popen(
            build_worker_command(adapter_name, language, relative_path),
            cwd=str(backend_root()),
            env=_worker_env(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=False,
        )
    except OSError as exc:
        return _infrastructure_failure(adapter_name, f"worker spawn failed ({type(exc).__name__})")
    try:
        assert proc.stdin is not None and proc.stdout is not None
        stdout, _ = proc.communicate(input=source, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return ParseResult(
            state=ParseState.FAILED,
            ncm=None,
            diagnostics=[
                Diagnostic(
                    severity="error",
                    message=f"Parser exceeded the per-file timeout ({timeout_s:g}s).",
                    location=None,
                    parser=adapter_name,
                    code="timeout",
                )
            ],
            parser_name=adapter_name,
            parser_version="",
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )
    except OSError as exc:
        proc.kill()
        proc.wait()
        return _infrastructure_failure(adapter_name, f"worker I/O failed ({type(exc).__name__})")
    if proc.returncode != 0:
        return _infrastructure_failure(
            adapter_name, f"parser worker terminated abnormally (exit {proc.returncode})"
        )
    try:
        payload = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return _infrastructure_failure(adapter_name, "parser worker emitted malformed output")
    if not isinstance(payload, dict) or "state" not in payload:
        return _infrastructure_failure(adapter_name, "parser worker emitted malformed output")
    if "error" in payload:
        return _infrastructure_failure(adapter_name, "parser worker reported an error")
    try:
        assert isinstance(payload, dict)
        return ParseResult.from_dict(payload)
    except (AssertionError, ValueError, KeyError, TypeError):
        return _infrastructure_failure(adapter_name, "parser worker result failed validation")


def _infrastructure_failure(adapter_name: str, message: str) -> ParseResult:
    return ParseResult(
        state=ParseState.FAILED,
        ncm=None,
        diagnostics=[
            Diagnostic(
                severity="error",
                message=message,
                location=None,
                parser=adapter_name,
                code="infrastructure",
            )
        ],
        parser_name=adapter_name,
        parser_version="",
    )
