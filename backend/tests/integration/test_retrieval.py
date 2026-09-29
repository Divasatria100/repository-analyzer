"""Live retrieval tests against local git fixture repos (no network).

The ``git`` binary is used as a content-addressing tool on synthetic local
repositories only. ``allow_local_paths`` is a test-only seam; production
calls derive an https remote from the validated identity.
"""

from pathlib import Path

import pytest

from app.core.config import load_settings
from app.repository.errors import (
    RetrievalIncompleteError,
    RetrievalSecurityError,
    RetrievalSizeLimitError,
    RetrievalTimeoutError,
)
from app.repository.identity import normalize_github_url
from app.repository.retrieval import (
    RetrievalResult,
    RetrievalService,
    RetrievalStatus,
    check_remote_size,
)
from tests.fixtures.helpers.canary import assert_canary_absent, fixture_contains_canary_payload
from tests.fixtures.helpers.paths import read_fixture_text
from tests.fixtures.helpers.repo_helpers import init_git_repo

pytestmark = pytest.mark.security

IDENTITY = normalize_github_url("https://github.com/fixture-owner/fixture-repo")

BASIC_FILES = {
    "main.py": 'def greet(name):\n    return f"hello {name}"\n',
    "requirements.txt": "requests==2.31.0\n",
}


def _service(**overrides: object) -> RetrievalService:
    settings = load_settings()
    operational = settings.operational
    network = settings.network
    params: dict[str, object] = {
        "repo_max_bytes": operational.repo_max_size_bytes,
        "file_max_bytes": operational.file_max_size_bytes,
        "max_files": operational.index_max_files,
        "max_depth": operational.index_max_depth,
        "storage_max_bytes": operational.analysis_storage_max_mb * 1024 * 1024,
        "retrieval_timeout_s": network.retrieval_total_s,
        "max_retries": network.retries_retrieval,
    }
    params.update(overrides)
    return RetrievalService(**params)  # type: ignore[arg-type]


def _retrieve(
    tmp_path: Path, files: dict[str, str], sha: str | None = None
) -> tuple[RetrievalResult, str]:
    source = tmp_path / "source"
    head = init_git_repo(source, files)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    result = _service().retrieve(
        identity=IDENTITY,
        commit_sha=sha or head,
        workspace=workspace,
        remote_url=str(source),
        allow_local_paths=True,
    )
    return result, head


def test_successful_retrieval_at_exact_commit(tmp_path: Path) -> None:
    result, head = _retrieve(tmp_path, BASIC_FILES)
    assert result.status == RetrievalStatus.COMPLETED
    assert result.commit_sha == head
    assert (result.workspace / "main.py").read_text(encoding="utf-8").startswith("def greet")
    assert (result.workspace / "requirements.txt").exists()
    assert not (result.workspace / ".repolens-git").exists()
    assert result.files_extracted == 2
    assert result.submodules_present is False


def test_canary_content_retrieved_never_executed(tmp_path: Path) -> None:
    canary = read_fixture_text("security", "execution_canary.py")
    assert fixture_contains_canary_payload(canary)
    files = dict(BASIC_FILES)
    files["canary_check.py"] = canary
    result, _ = _retrieve(tmp_path, files)
    assert result.status == RetrievalStatus.COMPLETED
    assert (result.workspace / "canary_check.py").exists()
    assert_canary_absent()


def test_wrong_commit_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    init_git_repo(source, BASIC_FILES)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(RetrievalSecurityError):
        _service().retrieve(
            identity=IDENTITY,
            commit_sha="f" * 40,
            workspace=workspace,
            remote_url=str(source),
            allow_local_paths=True,
        )


def test_missing_remote_fails_without_retry(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(RetrievalIncompleteError) as exc_info:
        _service().retrieve(
            identity=IDENTITY,
            commit_sha="a" * 40,
            workspace=workspace,
            remote_url=str(workspace / "does-not-exist"),
            allow_local_paths=True,
        )
    assert exc_info.value.retryable is False


def test_transient_failure_retried_then_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.repository.retrieval as retrieval_module

    source = tmp_path / "source"
    head = init_git_repo(source, BASIC_FILES)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    calls = {"count": 0}
    real_run_git = retrieval_module._run_git

    def flaky(argv: list[str], env: dict[str, str], timeout_s: float) -> object:
        calls["count"] += 1
        if calls["count"] == 1:
            raise retrieval_module.RetrievalTransportError()
        return real_run_git(argv, env, timeout_s)

    monkeypatch.setattr(retrieval_module, "_run_git", flaky)
    result = _service().retrieve(
        identity=IDENTITY,
        commit_sha=head,
        workspace=workspace,
        remote_url=str(source),
        allow_local_paths=True,
    )
    assert result.status == RetrievalStatus.COMPLETED
    assert calls["count"] >= 2


def test_retrieval_timeout_enforced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    source = tmp_path / "source"
    head = init_git_repo(source, BASIC_FILES)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    service = _service(retrieval_timeout_s=60.0, max_retries=0)

    def slow_popen(*args: object, **kwargs: object) -> object:
        raise subprocess.TimeoutExpired(cmd="git", timeout=0.01)

    monkeypatch.setattr("subprocess.Popen", slow_popen)
    with pytest.raises(RetrievalTimeoutError):
        service.retrieve(
            identity=IDENTITY,
            commit_sha=head,
            workspace=workspace,
            remote_url=str(source),
            allow_local_paths=True,
        )


def test_remote_size_precheck() -> None:
    check_remote_size(None, 100)
    check_remote_size(100, 100)
    with pytest.raises(RetrievalSizeLimitError):
        check_remote_size(101, 100)


def test_hook_payload_never_executes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    marker = tmp_path / "repolens-git-hook-canary.marker"
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    hook = read_fixture_text("repository-ingestion", "malicious-hooks", "post-checkout.sh")
    source = tmp_path / "source"
    init_git_repo(source, dict(BASIC_FILES))
    hooks_dir = source / ".git" / "hooks"
    (hooks_dir / "post-checkout").write_text(hook, encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    result = _service().retrieve(
        identity=IDENTITY,
        commit_sha=_head_of(source),
        workspace=workspace,
        remote_url=str(source),
        allow_local_paths=True,
    )
    assert result.status == RetrievalStatus.COMPLETED
    assert not marker.exists()
    assert_canary_absent()


def _head_of(source: Path) -> str:
    import subprocess

    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout.strip()


def test_smudge_filter_and_repo_config_never_execute(tmp_path: Path) -> None:
    import subprocess

    marker = tmp_path / "smudge.marker"
    source = tmp_path / "source"

    def git(*argv: str) -> None:
        subprocess.run(
            ["git", *argv],
            cwd=source,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            timeout=60,
        )

    attributes = read_fixture_text("repository-ingestion", "malicious-config", "repo.gitattributes")
    files = dict(BASIC_FILES)
    files[".gitattributes"] = attributes
    files["payload.bin"] = "RAW-BYTES-UNCHANGED\n"
    init_git_repo(source, files)
    git("config", "filter.test-smudge.smudge", f"touch {marker}")
    git("config", "credential.helper", f"touch {marker}")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    result = _service().retrieve(
        identity=IDENTITY,
        commit_sha=_head_of(source),
        workspace=workspace,
        remote_url=str(source),
        allow_local_paths=True,
    )
    assert result.status == RetrievalStatus.COMPLETED
    assert (workspace / "payload.bin").read_text(encoding="utf-8") == "RAW-BYTES-UNCHANGED\n"
    assert not marker.exists()


def test_submodule_contents_never_recursed(tmp_path: Path) -> None:
    import subprocess

    def git(*argv: str) -> None:
        subprocess.run(
            ["git", *argv],
            cwd=outer,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=True,
            timeout=60,
        )

    vendored = tmp_path / "vendored"
    init_git_repo(vendored, {"secret.py": "MARKER_UNRETRIEVED = True\n"})
    outer = tmp_path / "outer"
    outer.mkdir()
    git("init", "-b", "main")
    git("config", "user.email", "fixture@example.test")
    git("config", "user.name", "Fixture")
    (outer / "main.py").write_text("x = 1\n", encoding="utf-8")
    gitmodules = read_fixture_text("repository-ingestion", "submodule", ".gitmodules")
    (outer / ".gitmodules").write_text(gitmodules, encoding="utf-8")
    git("add", "-A")
    git("commit", "-m", "outer", "--no-gpg-sign")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    result = _service().retrieve(
        identity=IDENTITY,
        commit_sha=_head_of(outer),
        workspace=workspace,
        remote_url=str(outer),
        allow_local_paths=True,
    )
    assert result.status == RetrievalStatus.COMPLETED
    assert result.submodules_present is True
    assert not (workspace / "vendor" / "example" / "secret.py").exists()
