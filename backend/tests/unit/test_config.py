"""Configuration foundation tests (docs/15 §9.1, SECISO-907/908).

No test touches the network. Environment overrides use monkeypatched
``REPOLENS_*`` variables; the autouse ``isolated_settings`` fixture
guarantees a clean environment per test.
"""

import pytest
from pydantic import ValidationError

from app.core.config import format_validation_error, get_settings, load_settings
from app.main import build_app, create_app

_MB = 1024 * 1024

EXPECTED_DEFAULTS = {
    # (section, field, expected default)
    ("operational", "repo_max_size_bytes", 200 * _MB),
    ("operational", "file_max_size_bytes", 1 * _MB),
    ("operational", "index_max_files", 20000),
    ("operational", "index_max_depth", 32),
    ("operational", "analysis_timeout_total_s", 1800),
    ("operational", "parse_file_timeout_s", 30),
    ("operational", "analysis_memory_max_mb", 2048),
    ("operational", "analysis_storage_max_mb", 5120),
    ("operational", "graph_max_nodes", 10000),
    ("operational", "graph_max_edges", 50000),
    ("operational", "report_max_size_mb", 25),
    ("operational", "concurrency_max_analyses", 2),
    ("operational", "sweep_stale_threshold_h", 24),
    ("operational", "evidence_context_lines_each_side", 10),
    ("operational", "evidence_max_excerpt_lines", 40),
    ("operational", "api_page_size_default", 50),
    ("operational", "api_page_size_max", 200),
    ("network", "connect_timeout_s", 10),
    ("network", "read_timeout_s", 60),
    ("network", "retrieval_total_s", 600),
    ("network", "retries_metadata", 2),
    ("network", "retries_retrieval", 1),
    ("network", "advisory_timeout_s", 30),
}


def test_all_23_operational_values_have_required_defaults() -> None:
    settings = load_settings()
    assert len(EXPECTED_DEFAULTS) == 23
    for section, field_name, expected in EXPECTED_DEFAULTS:
        assert getattr(getattr(settings, section), field_name) == expected


def test_default_configuration_loads_correctly() -> None:
    settings = load_settings()
    assert settings.environment == "local"
    assert settings.resolved_log_level == "INFO"
    assert settings.database.url.startswith("postgresql")
    assert settings.application.name == "RepoLens API"


def test_valid_environment_overrides_work(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPOLENS_ENVIRONMENT", "test")
    monkeypatch.setenv("REPOLENS_OPERATIONAL__CONCURRENCY_MAX_ANALYSES", "4")
    monkeypatch.setenv("REPOLENS_NETWORK__RETRIES_METADATA", "3")
    monkeypatch.setenv("REPOLENS_DATABASE__URL", "postgresql+psycopg://db:5432/repolens_test")
    settings = load_settings()
    assert settings.environment == "test"
    assert settings.operational.concurrency_max_analyses == 4
    assert settings.network.retries_metadata == 3
    assert settings.database.url == "postgresql+psycopg://db:5432/repolens_test"
    assert settings.resolved_log_level == "WARNING"


def test_boundary_values_are_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REPOLENS_OPERATIONAL__INDEX_MAX_FILES", "1000")
    monkeypatch.setenv("REPOLENS_OPERATIONAL__INDEX_MAX_DEPTH", "64")
    monkeypatch.setenv("REPOLENS_NETWORK__CONNECT_TIMEOUT_S", "5")
    settings = load_settings()
    assert settings.operational.index_max_files == 1000
    assert settings.operational.index_max_depth == 64
    assert settings.network.connect_timeout_s == 5


@pytest.mark.parametrize(
    ("env_key", "env_value"),
    [
        ("REPOLENS_OPERATIONAL__REPO_MAX_SIZE_BYTES", str(9 * _MB)),  # below 10 MB min
        ("REPOLENS_OPERATIONAL__REPO_MAX_SIZE_BYTES", str(3 * 1024**3)),  # above 2 GB max
        ("REPOLENS_OPERATIONAL__INDEX_MAX_FILES", "999"),  # below min
        ("REPOLENS_OPERATIONAL__INDEX_MAX_DEPTH", "65"),  # above max
        ("REPOLENS_OPERATIONAL__CONCURRENCY_MAX_ANALYSES", "0"),  # below min
        ("REPOLENS_OPERATIONAL__CONCURRENCY_MAX_ANALYSES", "9"),  # above max
        ("REPOLENS_NETWORK__RETRIES_METADATA", "6"),  # above max
        ("REPOLENS_NETWORK__ADVISORY_TIMEOUT_S", "9"),  # below min
        ("REPOLENS_OPERATIONAL__INDEX_MAX_FILES", "not-a-number"),  # invalid type
        ("REPOLENS_ENVIRONMENT", "production"),  # invalid environment
    ],
)
def test_invalid_values_are_rejected(
    env_key: str, env_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(env_key, env_value)
    with pytest.raises(ValidationError):
        load_settings()


@pytest.mark.parametrize(
    ("env_key", "env_value"),
    [
        ("REPOLENS_OPERATIONAL__API_PAGE_SIZE_DEFAULT", "25"),  # Fixed at 50
        ("REPOLENS_OPERATIONAL__API_PAGE_SIZE_MAX", "100"),  # Fixed at 200
    ],
)
def test_fixed_values_cannot_be_configured(
    env_key: str, env_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """§9.1 Fixed values fail closed instead of being silently accepted."""
    monkeypatch.setenv(env_key, env_value)
    with pytest.raises(ValidationError):
        load_settings()


def test_pagination_default_and_maximum_are_enforced() -> None:
    settings = load_settings()
    assert settings.operational.api_page_size_default == 50
    assert settings.operational.api_page_size_max == 200
    assert settings.operational.api_page_size_default <= settings.operational.api_page_size_max


def test_invalid_evidence_window_relationship_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ±20-line window cannot fit in a 10-line excerpt cap."""
    monkeypatch.setenv("REPOLENS_OPERATIONAL__EVIDENCE_CONTEXT_LINES_EACH_SIDE", "20")
    monkeypatch.setenv("REPOLENS_OPERATIONAL__EVIDENCE_MAX_EXCERPT_LINES", "10")
    with pytest.raises(ValidationError):
        load_settings()


def test_database_settings_load_and_validate(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load_settings()
    assert "localhost" in settings.database.url
    assert settings.database.echo is False
    monkeypatch.setenv("REPOLENS_DATABASE__URL", "not-a-url")
    with pytest.raises(ValidationError):
        load_settings()


def test_http_client_settings_load_correctly() -> None:
    settings = load_settings()
    assert settings.network.connect_timeout_s == 10
    assert settings.network.read_timeout_s == 60
    assert settings.network.retrieval_total_s == 600


def test_application_initializes_with_valid_configuration() -> None:
    application = create_app(load_settings())
    assert application.state.settings.application.name == "RepoLens API"


def test_application_fails_closed_with_invalid_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REPOLENS_OPERATIONAL__GRAPH_MAX_NODES", "1")
    with pytest.raises(ValidationError):
        get_settings()


def test_format_validation_error_identifies_field_without_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REPOLENS_OPERATIONAL__CONCURRENCY_MAX_ANALYSES", "99")
    try:
        load_settings()
        raise AssertionError("expected ValidationError")
    except ValidationError as exc:
        report = format_validation_error(exc)
    assert "operational.concurrency_max_analyses" in report
    assert "99" not in report


def test_format_validation_error_never_exposes_database_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "REPOLENS_DATABASE__URL", "postgresql+psycopg://admin:hunter2@db:5432/repolens"
    )
    monkeypatch.setenv("REPOLENS_OPERATIONAL__GRAPH_MAX_NODES", "1")
    try:
        load_settings()
        raise AssertionError("expected ValidationError")
    except ValidationError as exc:
        report = format_validation_error(exc)
    assert "hunter2" not in report
    assert "database.url" in report or "operational.graph_max_nodes" in report


def test_startup_fails_closed_without_silent_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REPOLENS_OPERATIONAL__CONCURRENCY_MAX_ANALYSES", "99")
    with pytest.raises(SystemExit) as exc_info:
        build_app()
    assert "Invalid configuration" in str(exc_info.value.code)
    assert "operational.concurrency_max_analyses" in str(exc_info.value.code)


def test_startup_failure_hides_database_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "REPOLENS_DATABASE__URL", "postgresql+psycopg://admin:hunter2@db:5432/repolens"
    )
    monkeypatch.setenv("REPOLENS_OPERATIONAL__GRAPH_MAX_NODES", "1")
    with pytest.raises(SystemExit) as exc_info:
        build_app()
    report = str(exc_info.value.code)
    assert "hunter2" not in report
    assert "Invalid configuration" in report
