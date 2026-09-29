"""Non-execution canary tests (critical security baseline).

Concrete invariant (no stronger claim is made): the repository-analysis
test path below handles fixture content with non-executing operations
only — read as text, parse syntax, scan text — and the canary side
effects never occur. Future ingestion/parsing/analyzer tests must reuse
``assert_canary_absent`` after touching fixture content.
"""

import ast
import os

import pytest

from app.core.logging import redact_text
from tests.fixtures.helpers.canary import (
    CANARY_ENV_VAR,
    assert_canary_absent,
    canary_marker_path,
    fixture_contains_canary_payload,
)
from tests.fixtures.helpers.paths import FIXTURE_AREAS, fixture_path, read_fixture_text

pytestmark = pytest.mark.security

CANARY_RELATIVE = ("security", "execution_canary.py")


def _handle_fixture_without_executing() -> str:
    """The canonical non-executing pipeline: read -> parse -> scan."""
    source = read_fixture_text(*CANARY_RELATIVE)
    ast.parse(source)  # parsing is not executing
    redact_text(source)  # log-pipeline scan, also non-executing
    return source


def test_canary_payload_is_present_but_never_triggered() -> None:
    source = _handle_fixture_without_executing()
    assert fixture_contains_canary_payload(source)
    assert_canary_absent()


def test_canary_marker_path_is_deterministic_and_absent() -> None:
    assert canary_marker_path().name == "repolens-canary-py01.marker"
    assert not canary_marker_path().exists()
    assert os.environ.get(CANARY_ENV_VAR) is None


def test_fixture_files_are_not_pytest_collectable() -> None:
    """No fixture filename may match pytest collection or import patterns."""
    from tests.fixtures.helpers.paths import FIXTURES_ROOT

    offenders = [
        path
        for path in FIXTURES_ROOT.rglob("*.py")
        if path.name.startswith("test_")
        or path.name.endswith("_test.py")
        or path.name == "__init__.py"
        or path.name == "conftest.py"
    ]
    assert offenders == []


def test_fixture_areas_exist_with_content() -> None:
    for area in FIXTURE_AREAS:
        entries = [p for p in fixture_path(area).iterdir() if p.name != ".gitkeep"]
        assert entries, f"fixture area is empty: {area}"
