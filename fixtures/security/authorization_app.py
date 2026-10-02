"""Fixture data for SEC-POTENTIAL-AUTHORIZATION positive tests. Never executed."""

from db import get_session
from models import User


@app.get("/users/{user_id}")
def get_user(user_id):
    session = get_session()
    return session.query(User).filter(User.id == user_id).first()


@app.delete("/users/{user_id}")
def delete_account(user_id):
    session = get_session()
    session.query(User).filter(User.id == user_id).delete()
    return {"deleted": user_id}


@app.get("/admin/export")
def export_all():
    session = get_session()
    check_permission(session.current_user, "admin")
    return session.query(User).all()


@app.get("/admin/purge")
def purge_all():
    session = get_session()
    return session.query(User).delete()
