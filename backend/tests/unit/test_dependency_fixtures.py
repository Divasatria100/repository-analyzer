"""Repository fixture coverage (TASK-122).

Every file under ``fixtures/dependencies/`` is parsed according to its
inferred V1.0 format. All fixtures must parse without failure and must
contribute occurrences (non-vacuous: an empty inventory fails the test).
"""

from pathlib import Path

from app.analyzers.dependency.discovery import discover_from_index
from app.analyzers.dependency.models import SupportState
from app.analyzers.dependency.parsers import parse_manifest_text

FIXTURES_ROOT = Path(__file__).resolve().parents[3] / "fixtures" / "dependencies"


def _format_for(name: str) -> str:
    lowered = name.lower()
    if lowered.startswith("requirements"):
        return "requirements_txt"
    if lowered.startswith("pyproject"):
        return "pyproject_toml"
    if lowered.startswith("poetry"):
        return "poetry_lock"
    if lowered.startswith("pipfile"):
        return "pipfile_lock"
    if "lock" in lowered:
        return "package_lock_json"
    return "package_json"


def test_all_repository_fixtures_parse_with_occurrences() -> None:
    files = sorted(
        path for path in FIXTURES_ROOT.iterdir() if path.is_file() and path.name != "README.md"
    )
    assert len(files) >= 8  # six formats plus variants
    total_occurrences = 0
    for path in files:
        refs = discover_from_index([path.name])
        text = path.read_text(encoding="utf-8")
        if not refs.manifests:
            # Fixture names with a suffix (e.g. ``*.fixture``) are not
            # index-discoverable by name; parse them by inferred format.
            from app.analyzers.dependency.models import ManifestKind, ManifestRef

            ecosystem = "npm" if "package" in path.name else "pypi"
            lockfile_formats = ("poetry_lock", "pipfile_lock", "package_lock_json")
            ref = ManifestRef(
                path=path.name,
                kind=(
                    ManifestKind.LOCKFILE
                    if _format_for(path.name) in lockfile_formats
                    else ManifestKind.MANIFEST
                ),
                format=_format_for(path.name),
                ecosystem=ecosystem,
                project_context="",
            )
        else:
            ref = refs.manifests[0]
        outcome = parse_manifest_text(text, ref)
        assert outcome.ref.support_state in (SupportState.SUPPORTED, SupportState.PARTIAL), (
            path.name,
            outcome.reasons,
        )
        assert outcome.occurrences, f"fixture contributed nothing: {path.name}"
        total_occurrences += len(outcome.occurrences)
    assert total_occurrences >= 10
