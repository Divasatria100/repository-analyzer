"""Fixture data for SEC-SENSITIVE-LOGGING positive tests. Never executed."""

import logging
import os

logger = logging.getLogger(__name__)


def login(request):
    password = request.json["password"]
    logger.info("password=%s", password)
    return password


def refresh():
    token = os.environ["API_TOKEN"]
    logger.info("token=%s", token)
    return token


def call_api(request):
    logger.info("Authorization: %s", request.headers["Authorization"])


def debug_user(user):
    logger.info(f"user={user} authenticated")


def trace_secret(secret):
    logger.info("secret=" + secret)
    logger.info("secret={}".format(secret))
    logger.info("secret=%s" % secret)


def show_account(account):
    logger.info(account.api_key)
