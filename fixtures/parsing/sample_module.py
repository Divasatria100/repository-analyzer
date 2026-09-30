"""Parser fixture: representative Python constructs (data only, never executed)."""

import os
import sys
from collections import defaultdict

import helpers
from . import sibling
from .sub import thing as aliased
from ..parent import other

CONSTANT = 42
CONFIG = {"retries": 3, "debug": False}


def create_engine(name, kind="default", *flags, mode, **options):
    """Build an engine description without side effects."""
    return {"name": name, "kind": kind}


class Registry(Base, Mixin):
    """Inert registry used only for parser coverage."""

    count = 0

    def __init__(self):
        self.items = []

    @property
    def size(self):
        """Number of registered items."""
        return len(self.items)

    @classmethod
    def describe(cls):
        """Describe the registry."""
        return cls.__name__

    @staticmethod
    def empty():
        return True

    def register(self, item, priority=0):
        """Record one item without side effects."""
        if not item:
            raise ValueError("missing item")
        try:
            self.items.append((item, priority))
        except TypeError as exc:
            raise ValueError("bad item") from exc
        else:
            return len(self.items)
        finally:
            self.count += 1

    async def load(self, source):
        """Pretend to load source without side effects."""
        async with open_async(source) as handle:
            rows = [line async for line in handle if line.strip()]
        return rows


def summarize(values):
    """Summarize values without side effects."""
    total = sum(v for v in values if v is not None)
    seen = 0
    for value in values:
        if value is None:
            continue
        seen += 1
    label = f"total={total}" if total else "empty"
    squared = [v * v for v in values]
    matrix = [[i + j for j in range(2)] for i in range(2)]
    while total > 100:
        total -= 1
    return label, squared, matrix


async def main(argv=None):
    """Entry point that performs no I/O when imported."""
    args = argv if argv is not None else []
    code = 0
    match args:
        case []:
            code = 1
        case [single]:
            code = len(single)
        case _:
            code = 0
    with open("out.txt", "w", encoding="utf-8") as handle:
        handle.write(str(code))
    return code
