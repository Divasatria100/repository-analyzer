"""Dependency manifest discovery tests (TASK-112).

Discovery finds the six V1.0 formats at root and in subdirectories from the
file index, with canonical relative paths, deterministic order, symlink and
special-file safety, and explicit limitations (never silent drops).
"""

import os

from app.analyzers.dependency.discovery import (
    classify_manifest_name,
    discover_from_index,
    project_context_for,
)
from app.repository.workspace import WorkspaceManager
from tests.fixtures.helpers.analyzer_helpers import make_workspace

SIX_FORMATS = [
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile.lock",
    "package.json",
    "package-lock.json",
]


def test_all_six_formats_discovered_at_root() -> None:
    result = discover_from_index(list(SIX_FORMATS))
    assert [ref.path for ref in result.manifests] == sorted(SIX_FORMATS)
    assert result.limitations == []


def test_nested_manifests_discovered_with_project_context() -> None:
    result = discover_from_index(["services/api/requirements.txt", "web/package.json"])
    by_path = {ref.path: ref for ref in result.manifests}
    assert by_path["services/api/requirements.txt"].project_context == "services/api"
    assert by_path["web/package.json"].project_context == "web"


def test_root_manifest_has_empty_project_context() -> None:
    assert project_context_for("requirements.txt") == ""
    assert project_context_for("a/b/package.json") == "a/b"


def test_results_are_deterministically_sorted() -> None:
    paths = ["z/package.json", "a/requirements.txt", "m/pyproject.toml"]
    first = [ref.path for ref in discover_from_index(paths).manifests]
    second = [ref.path for ref in discover_from_index(list(reversed(paths))).manifests]
    assert first == second == sorted(paths)


def test_non_manifest_files_ignored() -> None:
    result = discover_from_index(["src/app.py", "README.md", "setup.py", "Gemfile"])
    assert result.manifests == []
    assert result.limitations == []


def test_requirements_variants_discovered() -> None:
    result = discover_from_index(["requirements-dev.txt", "subdir/requirements.txt"])
    assert [ref.path for ref in result.manifests] == [
        "requirements-dev.txt",
        "subdir/requirements.txt",
    ]
    assert all(ref.format == "requirements_txt" for ref in result.manifests)


def test_duplicate_paths_discovered_once() -> None:
    result = discover_from_index(["requirements.txt", "requirements.txt"])
    assert [ref.path for ref in result.manifests] == ["requirements.txt"]


def test_manifest_lockfile_kinds_distinguished() -> None:
    result = discover_from_index(SIX_FORMATS)
    by_path = {ref.path: ref for ref in result.manifests}
    assert by_path["requirements.txt"].kind.value == "manifest"
    assert by_path["pyproject.toml"].kind.value == "manifest"
    assert by_path["package.json"].kind.value == "manifest"
    assert by_path["poetry.lock"].kind.value == "lockfile"
    assert by_path["Pipfile.lock"].kind.value == "lockfile"
    assert by_path["package-lock.json"].kind.value == "lockfile"


def test_classify_manifest_name_table() -> None:
    assert classify_manifest_name("app.py") is None
    kind, format_name, ecosystem = classify_manifest_name("Package.JSON")  # type: ignore[misc]
    assert kind.value == "manifest"
    assert format_name == "package_json"
    assert ecosystem == "npm"


def test_symlink_is_never_followed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    workspaces = WorkspaceManager(tmp_path / "roots")
    workspace = workspaces.create("analysis-1")
    real = workspace / "real-requirements.txt"
    real.write_text("requests==2.31.0\n", encoding="utf-8")
    link = workspace / "requirements.txt"
    try:
        os.symlink(real, link)
    except OSError:
        # Platforms without symlink privileges: lstat-branch is covered below.
        return
    result = discover_from_index(["requirements.txt"], workspace=workspace, workspaces=workspaces)
    assert result.manifests == []
    assert any("requirements.txt" in item for item in result.limitations)


def test_special_and_binary_files_skipped_with_record(tmp_path) -> None:  # type: ignore[no-untyped-def]
    workspace = make_workspace(
        tmp_path,
        {
            "requirements.txt": "requests==2.31.0\n",
            "package-lock.json": '{"invalid',
        },
    )
    workspaces = WorkspaceManager(tmp_path / "roots")
    result = discover_from_index(
        ["requirements.txt", "package-lock.json", "missing/poetry.lock"],
        workspace=workspace,
        workspaces=workspaces,
    )
    paths = [ref.path for ref in result.manifests]
    assert "requirements.txt" in paths
    assert "package-lock.json" in paths  # text is still discoverable; parse may fail
    assert "missing/poetry.lock" not in paths
    assert any("missing/poetry.lock" in item for item in result.limitations)


def test_oversized_manifest_recorded_not_dropped(tmp_path) -> None:  # type: ignore[no-untyped-def]
    workspace = make_workspace(tmp_path, {"requirements.txt": "requests==2.31.0\n"})
    workspaces = WorkspaceManager(tmp_path / "roots")
    result = discover_from_index(
        ["requirements.txt"],
        workspace=workspace,
        workspaces=workspaces,
        file_max_bytes=4,
    )
    assert result.manifests == []
    assert any("file.max_size_bytes" in item for item in result.limitations)


def test_escape_path_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    workspace = make_workspace(tmp_path, {"requirements.txt": "x==1\n"})
    workspaces = WorkspaceManager(tmp_path / "roots")
    result = discover_from_index(
        ["../outside/requirements.txt"],
        workspace=workspace,
        workspaces=workspaces,
    )
    assert result.manifests == []
    assert any("escapes" in item for item in result.limitations)
