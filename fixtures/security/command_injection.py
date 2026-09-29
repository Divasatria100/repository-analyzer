"""Fixture data for future SEC-COMMAND-INJECTION tests. Never executed."""

import os


def convert(filename):
    os.system("convert " + filename + " out.png")
