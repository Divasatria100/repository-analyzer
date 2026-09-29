"""Fixture data for future fan-out tests (one hub, many leaves). Never executed."""

import billing
import inventory
import notifications
import pricing
import reporting
import shipping


def refresh_all():
    return [billing.sync(), inventory.sync(), notifications.sync()]
