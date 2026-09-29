"""Fixture data for future architecture tests (clean layered imports). Never executed."""

from architecture_simple_store import load_record
from architecture_simple_render import render_row


def show_order(order_id):
    return render_row(load_record(order_id))
