"""Temporary repository helpers: build repo-like trees as data, never execute."""

import subprocess
from pathlib import Path


def make_temp_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    """Write ``{relative_path: content}`` into a fresh dir; returns the dir.

    Parent directories are created, paths stay inside ``tmp_path``, and the
    pytest ``tmp_path`` fixture removes everything afterwards. Contents are
    written as data — nothing here imports or runs them.
    """
    root = tmp_path / "repo"
    resolved_root = root.resolve()
    for relpath, content in files.items():
        target = (root / relpath).resolve()
        try:
            target.relative_to(resolved_root)
        except ValueError:
            raise ValueError(f"Refusing path escaping the temp repo: {relpath!r}") from None
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


def copy_fixture_tree(dest: Path, *parts: str) -> Path:
    """Copy a canonical fixture subtree into ``dest`` for mutation-safe tests."""
    import shutil

    from .paths import fixture_path

    source = fixture_path(*parts)
    target = dest / source.name
    shutil.copytree(source, target)
    return target


def init_git_repo(path: Path, files: dict[str, str], branch: str = "main") -> str:
    """Create a real local git repo from synthetic files; return HEAD SHA.

    Uses the ``git`` binary as a content-addressing tool only: files are
    written as data and committed, never executed. Honors the ambient
    developer git config for identity via ``-c`` overrides (no global writes).
    """

    def git(*argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *argv],
            cwd=path,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )

    path.mkdir(parents=True, exist_ok=True)
    git("init", "-b", branch)
    git("config", "user.email", "fixture@example.test")
    git("config", "user.name", "Fixture")
    git("config", "commit.gpgsign", "false")
    for relpath, content in files.items():
        target = path / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    git("add", "-A")
    git("commit", "-m", "fixture commit", "--no-gpg-sign")
    return git("rev-parse", "HEAD").stdout.strip()
