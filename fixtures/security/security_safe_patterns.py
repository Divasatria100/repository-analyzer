"""Fixture data for security negative tests. Never executed."""

import os
import sqlite3
import subprocess

import requests

FIXED_DB = "example.db"
REPORT_DIR = "/srv/reports/daily.txt"
USERS_URL = "https://api.example.com/users"


def find_user_safe(user_id):
    conn = sqlite3.connect(FIXED_DB)
    return conn.execute("SELECT * FROM users WHERE id = %s", (user_id,)).fetchall()


def fixed_status():
    subprocess.run(["git", "status"], check=True)


def read_fixed():
    with open(REPORT_DIR) as handle:
        return handle.read()


def list_users():
    return requests.get(USERS_URL).json()


def unrelated(value):
    return os.path.basename("fixed") + str(len(value))
