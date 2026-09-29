"""Fixture data for future SEC-PATH-TRAVERSAL tests. Never executed."""


def read_report(name):
    with open("/srv/reports/" + name) as handle:
        return handle.read()
