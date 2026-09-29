"""Configuration test helpers. Never bypass production validation."""

import pytest

from app.core.config import Settings, load_settings


def valid_settings() -> Settings:
    """Load default settings (fails closed on invalid environment)."""
    return load_settings()


def override_env(monkeypatch: pytest.MonkeyPatch, values: dict[str, str]) -> None:
    """Set REPOLENS_* environment overrides for one test."""
    for key, value in values.items():
        monkeypatch.setenv(key, value)
