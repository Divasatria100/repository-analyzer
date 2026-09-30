"""Parser fixture: valid prefix followed by trailing garbage (data only).

Tree-sitter recovers the leading statements and reports the trailing
region as an error; the result must be partial, never clean.
"""


def first():
    """First function parses normally."""
    return 1


def second():
    return 2


def broken(:
    pass
