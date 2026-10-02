"""Fixture data for SEC-POTENTIAL-AUTHORIZATION negative tests. Never executed."""

from db import get_session
from models import User


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/public")
def public_page():
    return {"message": "hello"}


@app.get("/users/me")
def get_self(current_user=Depends(require_admin)):
    return current_user


@app.post("/admin/users")
def create_user(payload):
    require_role("admin")
    session = get_session()
    user = User(**payload)
    session.add(user)
    return user
