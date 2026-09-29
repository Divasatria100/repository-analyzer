"""Fixture data: one half of a circular import pair. Never executed."""

from circular_beta import current_session


def current_user():
    return current_session().user
