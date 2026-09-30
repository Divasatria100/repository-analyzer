"""Fixture path helpers: locate the canonical root ``fixtures/`` tree."""

from pathlib import Path

# backend/tests/fixtures/helpers/ -> backend/tests -> backend -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[4]
FIXTURES_ROOT = REPO_ROOT / "fixtures"

FIXTURE_AREAS = (
    "security",
    "dependencies",
    "architecture",
    "code-structure",
    "malformed",
    "parsing",
)


def fixture_path(*parts: str) -> Path:
    """Resolve a path inside the canonical root fixtures tree."""
    return FIXTURES_ROOT.joinpath(*parts)


def read_fixture_text(*parts: str) -> str:
    """Read a fixture file as text (data, never executed)."""
    return fixture_path(*parts).read_text(encoding="utf-8")


def read_fixture_bytes(*parts: str) -> bytes:
    """Read a fixture file as bytes (data, never executed)."""
    return fixture_path(*parts).read_bytes()
