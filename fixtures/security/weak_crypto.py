"""Fixture data for future SEC-WEAK-CRYPTO tests. Never executed."""

import hashlib


def fingerprint(data):
    return hashlib.md5(data).hexdigest()
