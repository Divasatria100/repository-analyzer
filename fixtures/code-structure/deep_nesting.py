"""Fixture data for future nesting-depth tests. Never executed."""


def validate(payload):
    if payload:
        for row in payload:
            if row:
                for cell in row:
                    if cell:
                        return cell
    return None
