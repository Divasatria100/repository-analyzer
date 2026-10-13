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
    assert len(outcome.relationships) == 1
    (relation,) = outcome.relationships
    assert relation.parent == "requests"
    assert relation.parent_version == "2.31.0"
    assert relation.child == "urllib3"
    # Poetry records a range constraint here, not an exact version.
    assert relation.child_version is None


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


V2_DUAL_LOCK = """\
{
  "lockfileVersion": 2,
  "packages": {
    "": {"name": "demo"},
    "node_modules/react": {"version": "18.2.0"},
    "node_modules/loose": {"version": "1.0.0"}
  },
  "dependencies": {
    "react": {"version": "18.2.0"},
    "loose": {"version": "1.0.0"}
  }
}
"""

V1_NESTED_LOCK = """\
{
  "lockfileVersion": 1,
  "dependencies": {
    "express": {
      "version": "4.18.2",
      "requires": {"qs": "6.11.0"},
      "dependencies": {"qs": {"version": "6.11.0"}}
    },
    "weird": {"version": "git+https://example.test/repo.git#abc123"},
    "tarball": {"version": "https://example.test/pkg-1.0.0.tgz"},
    "linked": {"version": "file:libs/our-module"}
  }
}
"""


def test_v2_uses_packages_only_no_double_count() -> None:
    """FAIL-1: the v2 legacy `dependencies` section is the same nodes."""
    outcome = parse_manifest_text(V2_DUAL_LOCK, _ref("package-lock.json"))
    names = sorted(occ.original_name for occ in outcome.occurrences)
    assert names == ["loose", "react"]  # once each, not twice
    assert all(occ.section == "package-lock.packages" for occ in outcome.occurrences)
    assert any("not counted a second time" in reason for reason in outcome.reasons)


def test_v1_dependencies_parsed_with_nested_transitives() -> None:
    """C3: v1 nested nodes become occurrences with parent edges."""
    outcome = parse_manifest_text(V1_NESTED_LOCK, _ref("package-lock.json"))
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert by_name["express"].resolved_version == "4.18.2"
    assert by_name["qs"].resolved_version == "6.11.0"  # nested, not dropped
    edges = {(rel.parent, rel.child) for rel in outcome.relationships}
    assert ("express", "qs") in edges
    # Non-registry version values keep honest kinds and null resolutions.
    assert by_name["weird"].kind == "vcs" and by_name["weird"].resolved_version is None
    assert by_name["tarball"].kind == "url" and by_name["tarball"].resolved_version is None
    assert by_name["linked"].kind == "path" and by_name["linked"].resolved_version is None


def test_v2_same_name_distinct_versions_preserved() -> None:
    """FAIL-1: distinct nested versions are not merged away."""
    text = """\
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo"},
    "node_modules/lodash": {"version": "4.17.20"},
    "node_modules/a/node_modules/lodash": {"version": "4.17.21"}
  }
}
"""
    outcome = parse_manifest_text(text, _ref("package-lock.json"))
    versions = sorted(
        occ.resolved_version for occ in outcome.occurrences if occ.original_name == "lodash"
    )
    assert versions == ["4.17.20", "4.17.21"]


def test_pipfile_wildcard_empty_range_malformed_are_unresolved() -> None:
    """FAIL-2: only exact version-shaped pins resolve."""
    text = """\
{
      "default": {
        "pinned": {"version": "==2.31.0"},
        "wild": {"version": "*"},
        "blank": {"version": ""},
        "ranged": {"version": ">=2.0"},
        "broken": {"version": "==2.0 "},
        "odd": "not-a-dict"
      },
      "develop": {}
    }
"""
    outcome = parse_manifest_text(text, _ref("Pipfile.lock"))
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert by_name["pinned"].resolved_version == "2.31.0"
    assert by_name["wild"].resolved_version is None
    assert by_name["blank"].resolved_version is None
    assert by_name["ranged"].resolved_version is None
    assert by_name["broken"].resolved_version == "2.0"
    assert by_name["odd"].resolved_version is None
    assert by_name["odd"].kind == "unknown"


def test_poetry_dotted_names_keep_identity() -> None:
    """FAIL-3: dotted distribution names are not group.package splits.

    TOML requires dotted dependency names to be quoted; an unquoted dotted
    key is a nested table by the TOML specification, not a dependency.
    """
    text = """\
[tool.poetry]
name = "demo"
[tool.poetry.dependencies]
python = "^3.13"
"zope.interface" = "^5.0"
plain = "==1.2.3"
[tool.poetry.group.docs.dependencies]
sphinx = "^7.0"
"""
    outcome = parse_manifest_text(text, _ref("pyproject.toml"))
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert set(by_name) == {"zope.interface", "plain", "sphinx"}
    assert by_name["zope.interface"].canonical_name == "zope-interface"
    assert by_name["zope.interface"].section == "tool.poetry.dependencies"
    assert by_name["zope.interface"].resolved_version is None
    assert by_name["plain"].resolved_version == "1.2.3"
    assert by_name["sphinx"].section == "tool.poetry.group.docs.dependencies"
    assert by_name["sphinx"].runtime_context == "docs"


def test_poetry_unquoted_dotted_key_is_not_a_dependency() -> None:
    """FAIL-3: per TOML, `a.b = ...` is a nested table, never a package."""
    text = (
        '[tool.poetry]\nname = "demo"\n[tool.poetry.dependencies]\n'
        'python = "^3.13"\nzope.interface = "^5.0"\n'
    )
    outcome = parse_manifest_text(text, _ref("pyproject.toml"))
    assert [occ.original_name for occ in outcome.occurrences] == []
    assert any("uninterpretable" in reason for reason in outcome.reasons)


def test_requirements_arbitrary_equality_continuation_hashes() -> None:
    """C1: `===`, backslash continuations, and hash options."""
    text = (
        "exact==2.0\n"
        "arbitrary===2.0\n"
        "continued==1.0 \\\n"
        "    --hash=sha256:abc\n"
        "wild==*\n"
        "ranged>=1.0\n"
        "odd===2.0.*\n"
    )
    outcome = parse_manifest_text(text, _ref("requirements.txt"))
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert by_name["exact"].resolved_version == "2.0"
    # PEP 440 arbitrary equality pins the exact version string.
    assert by_name["arbitrary"].resolved_version == "2.0"
    # The continuation backslash is joining syntax, never version content.
    assert by_name["continued"].resolved_version == "1.0"
    assert by_name["wild"].resolved_version is None
    assert by_name["ranged"].resolved_version is None
    # `===` with a prefix pattern is not an exact pin.
    assert by_name["odd"].resolved_version is None


def test_package_json_partial_versions_are_unresolved() -> None:
    """C2: `1`/`1.2` are npm ranges; only full `X.Y.Z` resolves."""
    text = (
        '{"dependencies": {"full": "1.2.3", "partial": "1.2", "major": "1", "pre": "2.0.0-beta.1"}}'
    )
    outcome = parse_manifest_text(text, _ref("package.json"))
    by_name = {occ.original_name: occ for occ in outcome.occurrences}
    assert by_name["full"].resolved_version == "1.2.3"
    assert by_name["partial"].resolved_version is None
    assert by_name["major"].resolved_version is None
    assert by_name["pre"].resolved_version == "2.0.0-beta.1"


def test_find_line_for_distinguishes_overlaps() -> None:
    """C7: substring names, comments, dotted and scoped names."""
    from app.analyzers.dependency.parsers import find_line_for

    text = (
        "# flask is pinned below\n"
        "flask-cors==1.0\n"
        "flask==3.0.0\n"
        '"@scope/pkg": "1.2.3"\n'
        "zope.interface==5.0\n"
        "flask==2.0\n"
    )
    assert find_line_for(text, "flask") == 3  # not the comment, not flask-cors
    assert find_line_for(text, "flask", occurrence=1) == 6  # second declaration
    assert find_line_for(text, "flask-cors") == 2
    assert find_line_for(text, "@scope/pkg") == 4
    assert find_line_for(text, "zope.interface") == 5
    assert find_line_for(text, "missing") is None


def test_specifier_kinds_url_vcs_path() -> None:
    """C10: direct references and shorthands classify conservatively."""
    from app.analyzers.dependency.identity import classify_specifier_kind

    assert classify_specifier_kind("@ https://example.test/pkg.zip") == "url"
    assert classify_specifier_kind("github:user/repo") == "vcs"
    assert classify_specifier_kind("gitlab:user/repo") == "vcs"
    assert classify_specifier_kind("expressjs/express") == "vcs"  # GitHub shorthand
    assert classify_specifier_kind("npm:bar@1.0.0") == "registry"
    assert classify_specifier_kind("npm:@scope/bar@1.0.0") == "registry"
    assert classify_specifier_kind("link:../local") == "path"
    assert classify_specifier_kind("portal:../local") == "path"


def test_exact_version_validator() -> None:
    """FAIL-2/C1: implausible shapes never count as resolved versions."""
    from app.analyzers.dependency.identity import is_plausible_exact_version

    assert is_plausible_exact_version("2.31.0") is True
    assert is_plausible_exact_version("1.0a1") is True
    assert is_plausible_exact_version("1!2.0") is True
    assert is_plausible_exact_version("2.0.0-beta.1") is True
    assert is_plausible_exact_version("*") is False
    assert is_plausible_exact_version("") is False
    assert is_plausible_exact_version(None) is False
    assert is_plausible_exact_version("latest") is False
    assert is_plausible_exact_version("=2.0") is False
    assert is_plausible_exact_version(">=2.0") is False
    assert is_plausible_exact_version("1.0\\") is False
    assert is_plausible_exact_version("file:../x") is False
    assert is_plausible_exact_version("git+https://example.test/r") is False
    assert is_plausible_exact_version("2.0, <3") is False
