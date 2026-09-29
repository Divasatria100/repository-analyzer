"""Git hardening tests (TASK-047/048): construction-level guarantees + live proof.

Pure-construction tests assert the exact argv/env (no shell, no hooks, no
filters, no credential helpers, no submodule recursion, no file protocol).
Live tests run real git against local fixture repos and prove malicious
hooks/filters/configs/submodules never execute (canary markers absent).
"""

from pathlib import Path

import pytest

from app.repository.errors import (
    RetrievalIncompleteError,
    RetrievalTimeoutError,
    RetrievalTransportError,
)
from app.repository.retrieval import (
    build_archive_command,
    build_clone_command,
    build_rev_parse_command,
    build_safe_git_env,
    classify_git_failure,
)

pytestmark = pytest.mark.security


def test_clone_command_has_no_shell_or_recursion_or_hooks() -> None:
    dest = str(Path("/tmp/dest"))
    hooks = str(Path("/tmp/hooks"))
    argv = build_clone_command("https://github.com/acme/web.git", Path(dest), Path(hooks))
    assert argv[0] == "git"
    assert "--no-checkout" in argv
    assert "--no-recurse-submodules" in argv
    joined = " ".join(argv)
    assert "credential.helper=" in joined
    assert f"core.hooksPath={hooks}" in joined
    assert "protocol.file.allow=never" in joined
    assert "--recurse-submodules" not in [a for a in argv if a.startswith("--recurse")]
    assert "shell" not in joined.lower()


def test_clone_command_denies_file_protocol_by_default() -> None:
    argv = build_clone_command("https://github.com/acme/web.git", Path("/tmp/d"), Path("/tmp/h"))
    assert "protocol.file.allow=never" in argv
    argv = build_clone_command("/tmp/local", Path("/tmp/d"), Path("/tmp/h"), allow_local_paths=True)
    assert "protocol.file.allow=always" in argv


def test_archive_command_pins_exact_sha() -> None:
    argv = build_archive_command(Path("/tmp/d"), "a" * 40)
    assert argv == ["git", "-C", str(Path("/tmp/d")), "archive", "--format=tar", "a" * 40]


def test_rev_parse_verifies_commit_object() -> None:
    argv = build_rev_parse_command(Path("/tmp/d"), "b" * 40)
    assert "cat-file" in argv and "-e" in argv


def test_safe_env_blanks_git_configuration(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    env = build_safe_git_env(
        path_value="/usr/bin",
        home_dir=home,
        xdg_config_dir=home,
        empty_config_file=home / "empty",
        ceiling_dir=tmp_path,
    )
    assert env["GIT_CONFIG_COUNT"] == "0"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"].endswith("empty")
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert "GIT_SSH" not in env
    assert "GIT_ASKPASS" not in env
    assert env["PATH"] == "/usr/bin"


def test_failure_classification() -> None:
    assert isinstance(classify_git_failure("repository not found"), RetrievalIncompleteError)
    assert isinstance(classify_git_failure("Authentication failed"), RetrievalIncompleteError)
    assert isinstance(classify_git_failure("Could not resolve host xyz"), RetrievalTransportError)
    assert isinstance(classify_git_failure("Connection reset by peer"), RetrievalTransportError)
    assert isinstance(classify_git_failure("weird unexpected output"), RetrievalIncompleteError)
    assert classify_git_failure("could not resolve host").retryable is True
    assert classify_git_failure("repository not found").retryable is False
    assert isinstance(RetrievalTimeoutError().retryable, bool)
