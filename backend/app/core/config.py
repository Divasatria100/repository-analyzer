"""Centralized backend application configuration (foundation).

Single source of truth for every operational value defined in
``docs/15-security-and-isolation.md`` §9.1 (23 values). No configuration
value may live scattered across modules; everything environment-specific
is provided through ``REPOLENS_``-prefixed environment variables.

Scope distinction (see docs/09 §4, docs/11 §7.5, docs/15 §1.5)::

    RepoLens Database  →  SQLAlchemy  →  Alembic   (configured here)

    Analyzed GitHub Repository  →  never executed, never migrated.

Fail-closed behavior (SECISO-908): any out-of-range, unparseable, or
relationally invalid value raises ``pydantic.ValidationError`` during
settings initialization, so no analysis can run under invalid
configuration. There are no silent fallbacks to valid values.
"""

from functools import lru_cache
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Units: sizes in bytes unless the name states otherwise.
_MB = 1024 * 1024
_KB = 1024
_GB = 1024 * 1024 * 1024


class ApplicationSettings(BaseModel):
    """Non-operational application identity."""

    name: str = Field(default="RepoLens API", description="Application name.")
    version: str = Field(default="0.1.0", description="Application version.")
    debug: bool = Field(default=False, description="Debug mode. Never True with real data.")


class DatabaseSettings(BaseModel):
    """RepoLens application database only (PostgreSQL target).

    Never points at, migrates, or executes an analyzed repository.
    """

    url: str = Field(
        default="postgresql+psycopg://localhost:5432/repolens",
        description="SQLAlchemy database URL for the RepoLens database.",
    )
    echo: bool = Field(default=False, description="Echo SQL statements (debugging only).")

    @field_validator("url")
    @classmethod
    def _validate_url_format(cls, value: str) -> str:
        if "://" not in value or not value.split("://", 1)[0]:
            raise ValueError("database URL must be a valid SQLAlchemy URL (scheme://...)")
        return value


class NetworkSettings(BaseModel):
    """Outbound HTTP bounds. Maps 1:1 to §9.1 ``net.*`` and ``advisory.*``.

    Used by the HTTPX service-client foundation; GitHub/OSV integrations
    arrive in later phases and read these values instead of hardcoding.
    """

    connect_timeout_s: float = Field(
        default=10, ge=5, le=60, description="§9.1 net.connect_timeout_s (seconds)."
    )
    read_timeout_s: float = Field(
        default=60, ge=10, le=300, description="§9.1 net.read_timeout_s (seconds)."
    )
    retrieval_total_s: float = Field(
        default=600, ge=120, le=3600, description="§9.1 net.retrieval_total_s (seconds)."
    )
    retries_metadata: int = Field(
        default=2, ge=0, le=5, description="§9.1 net.retries_metadata (retries)."
    )
    retries_retrieval: int = Field(
        default=1, ge=0, le=3, description="§9.1 net.retries_retrieval (retries)."
    )
    advisory_timeout_s: float = Field(
        default=30, ge=10, le=120, description="§9.1 advisory.timeout_s (seconds)."
    )


class OperationalSettings(BaseModel):
    """Resource, concurrency, sweep, evidence, and pagination values (§9.1).

    ``api.page_size_default`` / ``api.page_size_max`` are Fixed by §9.1:
    they are modeled as literals, so any environment override attempting
    to change them fails closed instead of being silently accepted.
    """

    repo_max_size_bytes: int = Field(
        default=200 * _MB,
        ge=10 * _MB,
        le=2 * _GB,
        description="§9.1 repo.max_size_bytes.",
    )
    file_max_size_bytes: int = Field(
        default=1 * _MB,
        ge=64 * _KB,
        le=10 * _MB,
        description="§9.1 file.max_size_bytes.",
    )
    index_max_files: int = Field(
        default=20000, ge=1000, le=100000, description="§9.1 index.max_files."
    )
    index_max_depth: int = Field(default=32, ge=8, le=64, description="§9.1 index.max_depth.")
    analysis_timeout_total_s: float = Field(
        default=1800, ge=300, le=7200, description="§9.1 analysis.timeout_total_s."
    )
    parse_file_timeout_s: float = Field(
        default=30, ge=5, le=300, description="§9.1 parse.file_timeout_s."
    )
    analysis_memory_max_mb: int = Field(
        default=2048, ge=512, le=8192, description="§9.1 analysis.memory_max_mb."
    )
    analysis_storage_max_mb: int = Field(
        default=5120, ge=1024, le=20480, description="§9.1 analysis.storage_max_mb."
    )
    graph_max_nodes: int = Field(
        default=10000, ge=1000, le=50000, description="§9.1 graph.max_nodes."
    )
    graph_max_edges: int = Field(
        default=50000, ge=5000, le=250000, description="§9.1 graph.max_edges."
    )
    report_max_size_mb: int = Field(
        default=25, ge=5, le=100, description="§9.1 report.max_size_mb."
    )
    concurrency_max_analyses: int = Field(
        default=2, ge=1, le=8, description="§9.1 concurrency.max_analyses."
    )
    sweep_stale_threshold_h: float = Field(
        default=24, ge=1, le=168, description="§9.1 sweep.stale_threshold_h."
    )
    evidence_context_lines_each_side: int = Field(
        default=10, ge=0, le=20, description="§9.1 evidence.context_lines_each_side."
    )
    evidence_max_excerpt_lines: int = Field(
        default=40, ge=10, le=100, description="§9.1 evidence.max_excerpt_lines."
    )
    api_page_size_default: Literal[50] = Field(
        default=50, description="§9.1 api.page_size_default (Fixed, non-configurable)."
    )
    api_page_size_max: Literal[200] = Field(
        default=200, description="§9.1 api.page_size_max (Fixed, non-configurable)."
    )

    @model_validator(mode="after")
    def _validate_relationships(self) -> "OperationalSettings":
        if self.api_page_size_default > self.api_page_size_max:
            raise ValueError("api.page_size_default must not exceed api.page_size_max")
        window = 2 * self.evidence_context_lines_each_side + 1
        if window > self.evidence_max_excerpt_lines:
            raise ValueError(
                "evidence window (2 * context_lines_each_side + 1) must fit "
                "within evidence.max_excerpt_lines"
            )
        return self


class LoggingSettings(BaseModel):
    """Logging foundation. ``level=None`` resolves per environment."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] | None = Field(
        default=None, description="Log level override; None resolves per environment."
    )


class Settings(BaseSettings):
    """Root settings. Read once at startup; invalid values fail closed."""

    model_config = SettingsConfigDict(
        env_prefix="REPOLENS_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["local", "test"] = Field(
        default="local", description="Runtime environment: local development or test."
    )
    application: ApplicationSettings = Field(default_factory=ApplicationSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    operational: OperationalSettings = Field(default_factory=OperationalSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    def describe(self) -> dict[str, Any]:
        """Operator-inspectable view of effective values (SECISO-907)."""
        return self.model_dump()

    @property
    def resolved_log_level(self) -> str:
        """Environment-appropriate log level (test quiets to WARNING)."""
        if self.logging.level is not None:
            return self.logging.level
        return "WARNING" if self.environment == "test" else "INFO"


def load_settings() -> Settings:
    """Build settings from environment. Raises ValidationError when invalid."""
    return Settings()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings for application runtime. Fails closed on invalid config."""
    return load_settings()
