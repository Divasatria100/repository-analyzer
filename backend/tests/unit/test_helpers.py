"""Common helper tests: utilities behave safely and deterministically."""

from pathlib import Path

import pytest

from app.core.database import session_scope
from tests.fixtures.helpers import canary as canary_helpers
from tests.fixtures.helpers import config_helpers, db_helpers, http_helpers, paths, repo_helpers


def test_read_fixture_as_data() -> None:
    text = paths.read_fixture_text("security", "hardcoded_secret.py")
    assert "FAKE_API_TOKEN_FOR_TESTING_0000" in text
    raw = paths.read_fixture_bytes("security", "hardcoded_secret.py")
    assert raw.decode("utf-8") == text


def test_fixture_paths_stay_inside_tree() -> None:
    assert paths.fixture_path("malformed", "syntax_error.py").is_file()
    assert paths.FIXTURES_ROOT.name == "fixtures"


def test_make_temp_repo_writes_and_isolates(tmp_path: Path) -> None:
    root = repo_helpers.make_temp_repo(
        tmp_path, {"pkg/mod.py": "x = 1\n", "README.md": "fixture\n"}
    )
    assert (root / "pkg" / "mod.py").read_text(encoding="utf-8") == "x = 1\n"
    with pytest.raises(ValueError, match="Refusing path"):
        repo_helpers.make_temp_repo(tmp_path, {"../escape.py": "x"})


def test_valid_settings_and_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = config_helpers.valid_settings()
    assert settings.operational.concurrency_max_analyses == 2
    config_helpers.override_env(
        monkeypatch, {"REPOLENS_OPERATIONAL__CONCURRENCY_MAX_ANALYSES": "1"}
    )
    from app.core.config import load_settings

    assert load_settings().operational.concurrency_max_analyses == 1


def test_sqlite_factory_roundtrip() -> None:
    engine, factory = db_helpers.make_sqlite_factory()
    try:
        with session_scope(factory) as session:
            assert session is not None
    finally:
        engine.dispose()


def test_route_transport_dispatches_by_path() -> None:
    import httpx

    transport = http_helpers.route_transport(
        {"/known": lambda request: http_helpers.json_response({"ok": True})}
    )
    client = httpx.Client(transport=transport, base_url="https://example.test")
    assert client.get("/known").json() == {"ok": True}
    assert client.get("/unknown").status_code == 404
    client.close()


def test_canary_helpers_are_inert() -> None:
    assert canary_helpers.fixture_contains_canary_payload("xx REPOLENS_CANARY_PY01_PAYLOAD yy")
    canary_helpers.assert_canary_absent()


def test_non_loopback_connections_are_blocked() -> None:
    import socket

    with pytest.raises(RuntimeError, match="External network blocked"):
        socket.socket().connect(("example.test", 443))
