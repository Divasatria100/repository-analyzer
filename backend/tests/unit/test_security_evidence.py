"""Security evidence tests (TASK-096).

Evidence keeps 10 lines before and 40 lines after the finding (frozen
window), redacted, and never a wholesale copy of source files. Source
unavailability produces an explicit limitation, not a silent gap.
"""

import pytest

from app.analyzers.security.evidence import (
    EVIDENCE_LINES_AFTER,
    EVIDENCE_LINES_BEFORE,
    EVIDENCE_MAX_EXCERPT_LINES,
    build_security_evidence,
)
from tests.fixtures.helpers.security_helpers import analyze_files


def _numbered(count: int) -> tuple[str, ...]:
    return tuple(f"line {number}" for number in range(1, count + 1))


def test_frozen_window_values_match_operational_settings() -> None:
    """The security window cites the frozen Phase 6 evidence values."""
    from app.core.config import OperationalSettings

    settings = OperationalSettings()
    assert EVIDENCE_LINES_BEFORE == settings.evidence_context_lines_each_side == 10
    assert EVIDENCE_LINES_AFTER == settings.evidence_max_excerpt_lines == 40
    assert EVIDENCE_MAX_EXCERPT_LINES == 51


def test_mid_file_window_is_ten_before_forty_after() -> None:
    """A finding at line 100 yields lines 90..140 (the frozen window)."""
    evidence = build_security_evidence(
        path="src/app.py",
        focus_start_line=100,
        focus_end_line=100,
        lines=_numbered(200),
    )
    assert evidence is not None
    assert evidence.path == "src/app.py"
    assert evidence.start_line == 90
    assert evidence.end_line == 140
    assert len(evidence.lines) == 51
    assert evidence.lines[10] == "line 100"
    assert evidence.truncated is False
    assert evidence.redacted is False


def test_ten_lines_before_and_forty_after() -> None:
    """Focus line keeps 10 lines before and 40 lines after."""
    evidence = build_security_evidence(
        path="src/app.py",
        focus_start_line=50,
        focus_end_line=50,
        lines=_numbered(200),
    )
    assert evidence is not None
    assert evidence.start_line == 40
    assert evidence.end_line == 90
    assert len(evidence.lines) == 51
    assert evidence.truncated is False
    assert evidence.redacted is False


def test_window_clamps_at_file_start() -> None:
    """Early focus lines clamp at line 1 without underflow."""
    evidence = build_security_evidence(
        path="src/app.py",
        focus_start_line=3,
        focus_end_line=3,
        lines=_numbered(200),
    )
    assert evidence is not None
    assert evidence.start_line == 1
    assert evidence.end_line == 43
    assert len(evidence.lines) == 43


def test_window_clamps_at_file_end() -> None:
    """Late focus lines clamp at the last line without overflow."""
    evidence = build_security_evidence(
        path="src/app.py",
        focus_start_line=198,
        focus_end_line=198,
        lines=_numbered(200),
    )
    assert evidence is not None
    assert evidence.start_line == 188
    assert evidence.end_line == 200
    assert len(evidence.lines) == 13


def test_wide_span_truncates_with_marker() -> None:
    """Over-cap multi-line spans trim to the cap, finding lines preserved."""
    evidence = build_security_evidence(
        path="src/app.py",
        focus_start_line=50,
        focus_end_line=80,
        lines=_numbered(200),
    )
    assert evidence is not None
    assert len(evidence.lines) == 51
    assert evidence.truncated is True
    text = "\n".join(evidence.lines)
    assert "line 50" in text and "line 80" in text


def test_secret_lines_are_redacted_with_flag() -> None:
    """Credential-shaped values are masked and the finding says so."""
    lines = list(_numbered(30))
    lines[14] = 'password = "hunter2-hunter2-secret"'
    evidence = build_security_evidence(
        path="src/app.py",
        focus_start_line=15,
        focus_end_line=15,
        lines=tuple(lines),
    )
    assert evidence is not None
    assert evidence.redacted is True
    assert "hunter2" not in "\n".join(evidence.lines)


def test_missing_source_returns_none() -> None:
    """Unavailable source yields None (callers record a limitation)."""
    assert (
        build_security_evidence(
            path="src/app.py",
            focus_start_line=1,
            focus_end_line=1,
            lines=None,
        )
        is None
    )
    assert (
        build_security_evidence(
            path="src/app.py",
            focus_start_line=0,
            focus_end_line=1,
            lines=_numbered(10),
        )
        is None
    )
    assert (
        build_security_evidence(
            path="src/app.py",
            focus_start_line=5,
            focus_end_line=500,
            lines=_numbered(10),
        )
        is None
    )


def test_whole_source_files_are_never_persisted() -> None:
    """A large file yields at most the capped window in every finding."""
    body = "".join(f"# padding line {number}\n" for number in range(1, 5001))
    source = (
        "import sqlite3\n"
        "def find(name):\n"
        "    conn = sqlite3.connect('x')\n"
        "    return conn.execute('SELECT * FROM u WHERE n = ' + name)\n" + body
    )
    result, _, _ = analyze_files({"app.py": source})
    assert result.findings
    for finding in result.findings:
        assert finding.evidence is not None
        assert len(finding.evidence.lines) <= 51


def test_finding_evidence_is_bounded_and_relative() -> None:
    """End-to-end findings carry repo-relative, bounded, redacted excerpts."""
    result, _, _ = analyze_files(
        {
            "pkg/app.py": (
                "import subprocess\n"
                "def ping(host):\n"
                "    subprocess.run('ping ' + host, shell=True)\n"
            )
        }
    )
    findings = [f for f in result.findings if f.rule_id == "SEC-COMMAND-INJECTION"]
    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence is not None
    assert evidence.path == "pkg/app.py"
    assert evidence.path == findings[0].location.file_path
    assert evidence.start_line == 1
    assert evidence.end_line == 3
    assert len(evidence.lines) == 3
    assert evidence.truncated is False


@pytest.mark.security
def test_no_absolute_paths_in_evidence() -> None:
    """Evidence never exposes workspace or host paths."""
    result, _, _ = analyze_files(
        {"app.py": ("import requests\ndef fetch(url):\n    return requests.get(url).text\n")}
    )
    assert result.findings
    for finding in result.findings:
        assert finding.evidence is not None
        assert not finding.evidence.path.startswith("/")
        assert "tmp" not in finding.evidence.path
