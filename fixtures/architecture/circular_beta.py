"""Fixture data: other half of a circular import pair. Never executed."""

from circular_alpha import current_user


def current_session():
    return {"user": current_user()}
