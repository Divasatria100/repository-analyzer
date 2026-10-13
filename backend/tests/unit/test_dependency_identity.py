"""Dependency identity and version-semantics tests (TASK-114).

Canonical names follow ecosystem rules (PEP 503 for PyPI, scope-preserving
for npm); declared constraints are never mistaken for resolved versions.
"""

from app.analyzers.dependency.identity import (
    canonical_name,
    classify_specifier_kind,
    identity_key,
    is_exact_pinned,
    normalize_npm_name,
    normalize_pypi_name,
    split_requirement_name,
)


def test_pypi_normalization_case_and_separators() -> None:
    assert normalize_pypi_name("Django") == "django"
    assert normalize_pypi_name("my_package") == "my-package"
    assert normalize_pypi_name("my.package") == "my-package"
    assert normalize_pypi_name("My--__Package..Name") == "my-package-name"


def test_npm_scoped_package_preserved() -> None:
    assert normalize_npm_name("@scope/package") == "@scope/package"
    assert normalize_npm_name("React") == "React"


def test_npm_canonical_passes_through_to_osv_query() -> None:
    """C9: npm identity preserves scope/case end to end."""
    import json

    import httpx

    from tests.fixtures.helpers.dependency_helpers import analyze_manifests, mock_osv_client

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"results": [{}]})

    analyze_manifests(
        {"package.json": '{"dependencies": {"@scope/pkg": "1.2.3"}}'},
        osv_client=mock_osv_client(handler),  # type: ignore[arg-type]
    )
    body = json.loads(seen[0].content.decode("utf-8"))
    assert body["queries"][0]["package"] == {"name": "@scope/pkg", "ecosystem": "npm"}


def test_ecosystem_rules_never_cross_applied() -> None:
    assert canonical_name("pypi", "My_Package") == "my-package"
    assert canonical_name("npm", "My_Package") == "My_Package"


def test_identity_keys_pypi_case_insensitive_npm_sensitive() -> None:
    assert identity_key("pypi", "Django") == identity_key("pypi", "django")
    assert identity_key("npm", "React") != identity_key("npm", "react")


def test_exact_pin_detection() -> None:
    assert is_exact_pinned("==2.31.0") is True
    assert is_exact_pinned("== 2.31.0") is True
    assert is_exact_pinned(">=2.30") is False
    assert is_exact_pinned(">=2.0,<3.0") is False
    assert is_exact_pinned("^18.2.0") is False
    assert is_exact_pinned("18.2.0") is True
    assert is_exact_pinned("*") is False
    assert is_exact_pinned(None) is False
    assert is_exact_pinned("") is False


def test_specifier_kinds() -> None:
    assert classify_specifier_kind(">=2.0") == "registry"
    assert classify_specifier_kind("https://example.test/pkg.tar.gz") == "url"
    assert classify_specifier_kind("git+https://example.test/repo.git") == "vcs"
    assert classify_specifier_kind("./local/path") == "path"
    assert classify_specifier_kind("-e ./local") == "editable"
    assert classify_specifier_kind(None) == "unknown"
    assert classify_specifier_kind("") == "unknown"


def test_requirement_splitting() -> None:
    assert split_requirement_name("requests==2.31.0") == ("requests", "==2.31.0")
    assert split_requirement_name("flask>=3.0") == ("flask", ">=3.0")
    assert split_requirement_name("requests[security]>=2.0") == ("requests", ">=2.0")
    name, constraint = split_requirement_name("Django")
    assert name == "Django" and constraint is None
    name, constraint = split_requirement_name("pkg @ https://example.test/pkg.zip")
    assert name == "pkg" and constraint == "@ https://example.test/pkg.zip"


def test_constraint_is_not_a_resolved_version() -> None:
    """``requests>=2.30`` constrains; it never resolves to ``2.30``."""
    from app.analyzers.dependency.analyzer import DictManifestProvider, build_inventory

    inventory = build_inventory(DictManifestProvider({"requirements.txt": "requests>=2.30\n"}))
    assert len(inventory.occurrences) == 1
    occurrence = inventory.occurrences[0]
    assert occurrence.constraint == ">=2.30"
    assert occurrence.resolved_version is None


def test_repeated_occurrences_preserved() -> None:
    from app.analyzers.dependency.analyzer import DictManifestProvider, build_inventory

    inventory = build_inventory(
        DictManifestProvider(
            {
                "requirements.txt": "requests==2.31.0\n",
                "services/api/requirements.txt": "requests==2.28.0\n",
            }
        )
    )
    matches = [occ for occ in inventory.occurrences if occ.canonical_name == "requests"]
    assert len(matches) == 2
    assert {occ.source_file for occ in matches} == {
        "requirements.txt",
        "services/api/requirements.txt",
    }
