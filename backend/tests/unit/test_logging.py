"""Logging foundation tests: levels resolve per environment, secrets redacted."""

import logging

from app.core.logging import (
    RedactingFilter,
    configure_logging,
    get_logger,
    redact_args,
    redact_text,
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
