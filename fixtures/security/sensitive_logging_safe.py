"""Fixture data for SEC-SENSITIVE-LOGGING negative tests. Never executed."""

import logging

logger = logging.getLogger(__name__)


def track(user_id, request_id, status):
    logger.info("user_id=%s", user_id)
    logger.info("request_id=%s", request_id)
    logger.info("status=%s", status)


def audit_password(password, token):
    logger.info("password=%s", mask(password))
    logger.info("token=%s", redact(token))
    logger.info("password present=%s", bool(password))
    logger.info("token length=%s", len(token))
    logger.info("token prefix=%s", token[:4])


def count_tokens(token, password):
    token_count = len(token)
    password_length = len(password)
    logger.info("token_count=%s", token_count)
    logger.info("password_length=%s", password_length)


def mask(value):
    return "***"


def redact(value):
    return "***"
