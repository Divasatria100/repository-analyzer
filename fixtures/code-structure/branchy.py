"""Fixture data for future complexity tests. Never executed."""


def classify(score, premium, region):
    if score > 90:
        if premium:
            if region == "eu":
                return "gold-eu"
            return "gold"
        return "silver"
    elif score > 50:
        return "bronze"
    return "none"
