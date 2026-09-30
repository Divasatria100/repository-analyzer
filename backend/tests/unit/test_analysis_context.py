"""AnalysisContext tests (TASK-083): frozen, minimal, infrastructure-free."""

import dataclasses

import pytest

from tests.fixtures.helpers.analyzer_helpers import make_context, make_ncm_repository


def test_required_fields_present() -> None:
    """Context carries identities, commit, NCM, config, versions, limitations."""
    context = make_context()
    assert context.analysis_id == "analysis-1"
    assert context.repository_id == "repo-1"
    assert context.resolved_commit_sha == "0" * 40
    assert context.ncm.analysis_id == "analysis-1"
    assert context.analyzer_version == "0.1.0"
    assert context.rule_set_version == "1.0"
    assert context.thresholds.fan_out == 7
    assert context.limitations == ()


def test_context_is_frozen() -> None:
    """Context is read-only: analyzers cannot mutate shared state."""
    context = make_context()
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.analysis_id = "other"  # type: ignore[misc]


def test_no_execution_or_network_facilities() -> None:
    """Context exposes no subprocess, shell, HTTP, or package-manager surface."""
    context = make_context()
    exposed = set(dir(context)) | set(context.describe())
    forbidden = {
        "http",
        "client",
        "session",
        "request",
        "socket",
        "subprocess",
        "shell",
        "command",
        "exec",
        "eval",
        "compile",
        "pip",
        "npm",
        "os",
        "sys",
        "path",
        "open",
        "github",
        "token",
        "secret",
        "password",
        "credential",
    }
    assert not (exposed & forbidden), exposed & forbidden


def test_describe_is_operator_safe() -> None:
    """describe() carries identities/versions only — no content, no secrets."""
    summary = make_context().describe()
    assert summary["analysis_id"] == "analysis-1"
    assert summary["resolved_commit_sha"] == "0" * 40
    assert "ncm_completeness" in summary
    assert "password" not in str(summary).lower()
    assert "secret" not in str(summary).lower()


def test_ncm_completeness_visible() -> None:
    """Analyzers can observe partial NCM through the context."""
    from app.ncm import NcmFileEntry, NcmRepository

    ncm = NcmRepository(
        analysis_id="analysis-1",
        files=[NcmFileEntry(path="a.py", language="python", parse_state="failed", module=None)],
    )
    assert make_ncm_repository("src/app.py").completeness == "complete"
    assert make_context(ncm=ncm).ncm.completeness == "incomplete"
