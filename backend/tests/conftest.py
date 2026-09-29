"""Shared test fixtures: isolated configuration, no external network."""

import os

import pytest

from app.api.deps import reset_session_factory
from app.core.config import get_settings


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear REPOLENS_ env vars and reset cached settings/factories per test."""
    for key in [key for key in os.environ if key.startswith("REPOLENS_")]:
        monkeypatch.delenv(key, raising=False)
    get_settings.cache_clear()
    reset_session_factory()
    yield
    get_settings.cache_clear()
    reset_session_factory()
