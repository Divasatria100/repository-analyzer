"""Logging foundation tests: levels resolve per environment, secrets redacted."""

import logging

from app.core.config import load_settings
from app.core.logging import (
    EventFormatter,
    RedactingFilter,
    clear_request_context,
    configure_logging,
    get_logger,
    log_event,
    log_exception,
    redact_args,
    redact_headers,
    redact_sensitive_data,
    redact_text,
    redact_url,
    set_request_context,
    summarize_settings_for_logging,
)


def test_redact_text_masks_credential_fragments() -> None:
    message = redact_text("login failed password=hunter2 for user")
    assert "hunter2" not in message
    assert "***" in message


def test_redact_args_masks_sensitive_mapping_values() -> None:
    redacted = redact_args({"username": "ada", "password": "hunter2", "nested": {"token": "abc"}})
    assert redacted == {"username": "ada", "password": "***", "nested": {"token": "***"}}


def test_redact_args_masks_sensitive_list_items() -> None:
    redacted = redact_args([{"api_key": "key-123"}, "plain"])
    assert redacted == [{"api_key": "***"}, "plain"]


def test_redacting_filter_cleans_record_before_emit() -> None:
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "token=%s", ("abc",), None)
    assert RedactingFilter().filter(record) is True
    assert record.getMessage() != "token=abc"


def test_configure_logging_sets_level_and_filter() -> None:
    logger = configure_logging("WARNING")
    assert logger.level == logging.WARNING
    assert any(isinstance(f, RedactingFilter) for f in logger.filters)


def test_child_logger_namespaced() -> None:
    assert get_logger("ingestion").name == "repolens.ingestion"


# --- TASK-026: headers, URLs, nested structures ---


def test_redact_headers_masks_sensitive_case_insensitively() -> None:
    redacted = redact_headers(
        {
            "Authorization": "Bearer hunter2",
            "COOKIE": "session=abc",
            "Set-Cookie": "id=1",
            "Content-Type": "application/json",
        }
    )
    assert redacted == {
        "Authorization": "***",
        "COOKIE": "***",
        "Set-Cookie": "***",
        "Content-Type": "application/json",
    }


def test_redact_url_scrubs_userinfo_password() -> None:
    redacted = redact_url("postgresql://admin:hunter2@db:5432/repolens")
    assert "hunter2" not in redacted
    assert "admin:" in redacted and "@db:5432" in redacted


def test_redact_url_scrubs_sensitive_query_params() -> None:
    redacted = redact_url("https://example.test/api?token=secret-value&repo=acme/web")
    assert "secret-value" not in redacted
    assert "repo=acme/web" in redacted


def test_redact_text_scrubs_urls_inside_free_text() -> None:
    message = redact_text("fetch failed for https://example.test/api?token=secret-value")
    assert "secret-value" not in message


def test_redact_sensitive_data_handles_nested_structures() -> None:
    redacted = redact_sensitive_data(
        {
            "username": "developer",
            "password": "secret",
            "nested": [{"token": "abc", "safe": 1}],
            "pair": ("a", "b"),
        }
    )
    assert redacted["password"] == "***"
    assert redacted["nested"] == [{"token": "***", "safe": 1}]
    assert redacted["pair"] == ("a", "b")


# --- TASK-025/026: structured events, context, emitted records ---


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _capturing_logger(name: str) -> tuple[logging.Logger, _Capture]:
    logger = configure_logging("DEBUG")
    capture = _Capture()
    logger.addHandler(capture)
    return get_logger(name), capture


def test_log_event_emits_stable_name_and_redacted_fields() -> None:
    logger, capture = _capturing_logger("events")
    log_event(
        logger,
        logging.INFO,
        "analysis.started",
        "Analysis started",
        analysis_id="a-1",
        password="hunter2",
    )
    assert len(capture.records) == 1
    record = capture.records[0]
    assert record.levelno == logging.INFO
    assert record.repolens_event == "analysis.started"
    assert "hunter2" not in record.getMessage()
    assert "analysis_id=a-1" in record.repolens_detail


def test_request_context_is_attached_to_records() -> None:
    logger, capture = _capturing_logger("context")
    set_request_context(request_id="r-1", analysis_id="a-2")
    try:
        log_event(logger, logging.INFO, "parser.failed", "Parse failed", file_path="x.py")
        assert capture.records[0].request_id == "r-1"
        assert capture.records[0].analysis_id == "a-2"
    finally:
        clear_request_context()
    log_event(logger, logging.INFO, "parser.failed", "Parse failed")
    assert capture.records[1].request_id == "-"


def test_log_exception_redacts_error_value() -> None:
    logger, capture = _capturing_logger("exceptions")
    try:
        raise ValueError("request failed with token=hunter2")
    except ValueError as exc:
        log_exception(logger, "advisory.request.failed", exc, "Advisory lookup failed")
    record = capture.records[0]
    assert record.levelno == logging.ERROR
    assert record.repolens_event == "advisory.request.failed"
    assert "hunter2" not in record.getMessage()
    assert "ValueError" in record.repolens_detail


def test_formatter_redacts_traceback_text() -> None:
    formatter = EventFormatter("%(message)s")
    try:
        raise RuntimeError("db password=hunter2 rejected")
    except RuntimeError:
        import sys

        text = formatter.formatException(sys.exc_info())
    assert "hunter2" not in text


def test_repository_secret_finding_logs_metadata_only() -> None:
    """SEC-HARDCODED-SECRET style finding: metadata is logged, value never is."""
    logger, capture = _capturing_logger("findings")
    log_event(
        logger,
        logging.WARNING,
        "analysis.completed",
        "Secret finding recorded",
        rule_id="SEC-HARDCODED-SECRET",
        file_path="config/example.env",
        line_number=12,
        severity="high",
    )
    rendered = capture.records[0].getMessage() + capture.records[0].repolens_detail
    assert "SEC-HARDCODED-SECRET" in rendered
    assert "config/example.env" in rendered
    assert "AKIAIOSFODNN7EXAMPLE" not in rendered


def test_summarize_settings_for_logging_hides_database_url() -> None:
    summary = summarize_settings_for_logging(load_settings())
    assert summary["database"]["url"] == "***"
    assert "postgresql" not in str(summary)
    assert summary["operational"]["concurrency_max_analyses"] == 2
