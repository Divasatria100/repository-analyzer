"""Direct/transitive classification tests (TASK-115).

Classification is evidence-based: manifest declarations are direct,
lockfile children are transitive only with recorded relationships, and
anything unsupported stays unknown (never fabricated).
"""

from app.analyzers.dependency.analyzer import DictManifestProvider, build_inventory

POETRY_LOCK = """\
[[package]]
name = "flask"
version = "3.0.0"
[package.dependencies]
werkzeug = ">=3.0"

[[package]]
name = "werkzeug"
version = "3.0.1"
"""

PACKAGE_LOCK = """\
{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo", "dependencies": {"react": "^18.2.0"}},
    "node_modules/react": {"version": "18.2.0"},
    "node_modules/loose": {"version": "1.0.0"}
  }
}
"""


def _classes(manifests: dict[str, str]) -> dict[str, str]:
    inventory = build_inventory(DictManifestProvider(manifests))
    return {occ.original_name: occ.dependency_class.value for occ in inventory.occurrences}


def test_manifest_declarations_are_direct() -> None:
    classes = _classes({"requirements.txt": "requests==2.31.0\n"})
    assert classes == {"requests": "direct"}


def test_lockfile_child_is_transitive_with_relationship() -> None:
    classes = _classes(
        {
            "pyproject.toml": '[project]\nname="d"\ndependencies=["flask==3.0.0"]\n',
            "poetry.lock": POETRY_LOCK,
        }
    )
    assert classes["flask"] == "direct"  # direct wins over lockfile node
    assert classes["werkzeug"] == "transitive"


def test_lockfile_without_manifest_stays_unknown() -> None:
    classes = _classes({"poetry.lock": POETRY_LOCK})
    assert classes["flask"] == "unknown"
    # werkzeug is a recorded child but with no manifest the parent is only a
    # lockfile node: the only supported conclusion with a relationship is
    # transitive for the child.
    assert classes["werkzeug"] == "transitive"


def test_manifest_without_lockfile_is_direct_only() -> None:
    classes = _classes({"package.json": '{"dependencies": {"react": "^18.2.0"}}'})
    assert classes == {"react": "direct"}


def test_npm_lockfile_relationships() -> None:
    inventory = build_inventory(
        DictManifestProvider(
            {
                "package.json": '{"dependencies": {"react": "^18.2.0"}}',
                "package-lock.json": PACKAGE_LOCK,
            }
        )
    )
    by_name = {occ.original_name: occ for occ in inventory.occurrences}
    assert by_name["react"].dependency_class.value == "direct"
    assert by_name["loose"].dependency_class.value == "unknown"


def test_multiple_project_contexts_not_merged() -> None:
    inventory = build_inventory(
        DictManifestProvider(
            {
                "a/requirements.txt": "requests==2.31.0\n",
                "b/requirements.txt": "flask==3.0.0\n",
            }
        )
    )
    contexts = {(occ.original_name, occ.project_context) for occ in inventory.occurrences}
    assert contexts == {("requests", "a"), ("flask", "b")}


def test_unresolved_relationship_never_fabricated() -> None:
    inventory = build_inventory(
        DictManifestProvider({"package-lock.json": '{"lockfileVersion": 3, "packages": {}}'})
    )
    assert inventory.outcomes[0].failed  # empty lockfile is a failure, not clean
