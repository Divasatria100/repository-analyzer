"""Fixture data for future SEC-DISABLED-TLS tests. Never executed."""

import httpx


def fetch_status():
    return httpx.get("https://status.example.test/", verify=False)
