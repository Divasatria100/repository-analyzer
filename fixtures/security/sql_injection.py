"""Fixture data for future SEC-SQL-INJECTION tests. Never executed."""

import sqlite3


def find_user(username):
    conn = sqlite3.connect("example.db")
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchall()
