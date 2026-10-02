"""Fixture data for future SEC-SSRF tests. Never executed."""

import urllib.request

import requests


def fetch_profile(user_url):
    response = requests.get(user_url)
    return response.text


def fetch_report(path):
    target = "https://api.example.com/proxy?url=" + path
    return requests.get(target).text


def fetch_legacy(location):
    return urllib.request.urlopen(location).read()
