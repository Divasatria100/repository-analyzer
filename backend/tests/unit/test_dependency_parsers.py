"""Manifest/lockfile parser tests (TASK-112/114).

All six V1.0 formats plus PEP 621/Poetry variants, monorepo contexts, and
malformed inputs (failed, never clean, never an exception).
"""

from app.analyzers.dependency.analyzer import DictManifestProvider, build_inventory
from app.analyzers.dependency.discovery import discover_from_index
from app.analyzers.dependency.models import ManifestRef, SupportState
from app.analyzers.dependency.parsers import parse_manifest_text

REQUIREMENTS = "requests==2.31.0\nflask>=3.0\n# comment\n\nDjango\n"

PYPROJECT_PEP621 = """\
[project]
name = "demo"
dependencies = ["requests>=2.30", "flask==3.0.0"]
[project.optional-dependencies]
test = ["pytest>=8.0"]
"""

PYPROJECT_POETRY = """\
[tool.poetry]
name = "demo"
[tool.poetry.dependencies]
python = "^3.13"
requests = "^2.31.0"
flask = {version = "==3.0.0", extras = ["async"]}
local = {path = "../local-pkg"}
vcs = {git = "https://example.test/repo.git"}
[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
"""

POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.31.0"
[package.dependencies]
urllib3 = ">=1.21.1"

[[package]]
name = "urllib3"
version = "2.2.0"
"""

PIPFILE_LOCK = """\
{"default": {"requests": {"version": "==2.31.0"}}, "develop": {"pytest": {"version": "==8.0.0"}}}
"""

PACKAGE_JSON = """\
{
  "dependencies": {"react": "^18.2.0", "@scope/pkg": "1.2.3"},
  "devDependencies": {"jest": "^29.0.0"},
  "optionalDependencies": {"fsevents": "~2.3.0"},
  "peerDependencies": {"react-dom": "^18.0.0"}
}
"""

PACKAGE_LOCK = """\
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo"},
    "node_modules/react": {"version": "18.2.0"},
    "node_modules/loose": {}
  }
}
"""


def _ref(path: str) -> ManifestRef:
    refs = discover_from_index([path]).manifests
    assert len(refs) == 1
    return refs[0]


def test_requirements_txt_parsing() -> None:
    outcome = parse_manifest_text(REQUIREMENTS, _ref("requirements.txt"))
    assert outcome.ref.support_state == SupportState.SUPPORTED
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert by_name["requests"].resolved_version == "2.31.0"
    assert by_name["flask"].resolved_version is None
    assert by_name["Django"].constraint is None
    assert all(occ.dependency_class.value == "direct" for occ in outcome.occurrences)
    assert outcome.occurrences[0].source_line == 1


def test_pyproject_pep621_sections() -> None:
    outcome = parse_manifest_text(PYPROJECT_PEP621, _ref("pyproject.toml"))
    sections = {occ.section for occ in outcome.occurrences}
    assert "project.dependencies" in sections
    assert "project.optional-dependencies.test" in sections
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert by_name["flask"].resolved_version == "3.0.0"
    assert by_name["requests"].resolved_version is None
    assert by_name["pytest"].runtime_context == "optional"


def test_pyproject_poetry_sections_not_confused_with_pep621() -> None:
    outcome = parse_manifest_text(PYPROJECT_POETRY, _ref("pyproject.toml"))
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert "python" not in by_name  # interpreter constraint is not a dependency
    assert by_name["requests"].constraint == "^2.31.0"
    assert by_name["requests"].resolved_version is None
    assert by_name["flask"].resolved_version == "3.0.0"
    assert by_name["local"].kind == "path"
    assert by_name["vcs"].kind == "vcs"
    assert by_name["pytest"].runtime_context == "development"


def test_poetry_lock_resolved_versions_and_relationships() -> None:
    outcome = parse_manifest_text(POETRY_LOCK, _ref("poetry.lock"))
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert by_name["requests"].resolved_version == "2.31.0"
    assert by_name["urllib3"].resolved_version == "2.2.0"
    assert ("requests", "urllib3") in outcome.relationships


def test_pipfile_lock_sections() -> None:
    outcome = parse_manifest_text(PIPFILE_LOCK, _ref("Pipfile.lock"))
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert by_name["requests"].resolved_version == "2.31.0"
    assert by_name["requests"].runtime_context == "runtime"
    assert by_name["pytest"].runtime_context == "development"


def test_package_json_sections() -> None:
    outcome = parse_manifest_text(PACKAGE_JSON, _ref("package.json"))
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert by_name["react"].constraint == "^18.2.0"
    assert by_name["react"].resolved_version is None  # range is not exact
    assert by_name["@scope/pkg"].canonical_name == "@scope/pkg"
    assert by_name["@scope/pkg"].resolved_version == "1.2.3"
    assert by_name["jest"].runtime_context == "development"
    assert by_name["fsevents"].runtime_context == "optional"
    assert by_name["react-dom"].runtime_context == "peer"


def test_package_lock_json_versions() -> None:
    outcome = parse_manifest_text(PACKAGE_LOCK, _ref("package-lock.json"))
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert by_name["react"].resolved_version == "18.2.0"
    assert by_name["loose"].resolved_version is None


def test_malformed_files_are_failed_not_clean() -> None:
    for path, text in [
        ("requirements.txt", "requests==2.31.0\n"),  # valid baseline below
        ("pyproject.toml", "dependencies = [unclosed\n"),
        ("Pipfile.lock", "{not json"),
        ("package.json", "{oops"),
        ("package-lock.json", "[1,2"),
        ("poetry.lock", "[[[unclosed"),
    ]:
        outcome = parse_manifest_text(text, _ref(path))
        if path == "requirements.txt":
            assert outcome.ref.support_state == SupportState.SUPPORTED
        else:
            assert outcome.ref.support_state == SupportState.FAILED
            assert outcome.occurrences == []
            assert outcome.reasons


def test_malformed_manifest_does_not_stop_siblings() -> None:
    inventory = build_inventory(
        DictManifestProvider({"package.json": "{oops", "requirements.txt": "requests==2.31.0\n"})
    )
    assert any(occ.canonical_name == "requests" for occ in inventory.occurrences)
    failed = [item for item in inventory.outcomes if item.failed]
    assert len(failed) == 1 and failed[0].ref.path == "package.json"


def test_monorepo_contexts_preserved() -> None:
    inventory = build_inventory(
        DictManifestProvider(
            {
                "services/api/package.json": PACKAGE_JSON,
                "web/package.json": '{"dependencies": {"react": "17.0.0"}}',
            }
        )
    )
    contexts = {occ.project_context for occ in inventory.occurrences}
    assert contexts == {"services/api", "web"}


def test_oversized_and_unreadable_manifest_recorded_failed() -> None:
    provider = DictManifestProvider({"requirements.txt": "requests==2.31.0\n"})
    inventory = build_inventory(provider)
    assert len(inventory.occurrences) == 1
    empty = DictManifestProvider({})
    assert build_inventory(empty).occurrences == []
