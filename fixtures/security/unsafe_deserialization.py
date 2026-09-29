"""Fixture data for future SEC-UNSAFE-DESERIALIZATION tests. Never executed."""

import pickle


def load_session(blob):
    return pickle.loads(blob)
