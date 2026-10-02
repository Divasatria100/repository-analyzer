"""Fixture data for SEC-HARDCODED-SECRET positive tests. Never executed.

All values below are fictitious and reserved for documentation/testing.
They are shaped like real credentials only to exercise the detector.
"""

AWS_ACCESS_KEY_ID = "AKIAY2P4R6T8W0A2C4E6"
API_TOKEN = "ghp_9f8b7a6c5d4e3f2a1b0c9d8e7f6a5b4c9d"
BEARER_TOKEN = "Bearer x7f3a9c2e5b1d8f4a6c0e2b5d9a3f7c1e4b2a"
DB_PASSWORD = "hunter2-hunter2-hunter2-hunter2"

PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7
VJTUt9Us8c79x7x7x7x7x7x7x7x7x7x7x7x7x7x7x7x7x7x7x7
-----END PRIVATE KEY-----"""

DATABASE_URL = "postgresql://app:hunter2-db-pass-42@db.internal:5432/appdb"


def connect():
    return DATABASE_URL
