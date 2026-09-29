"""Foundation test: the application boots and the health endpoint responds."""

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


def test_health() -> None:
    client = TestClient(create_app(Settings(environment="test")))
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
