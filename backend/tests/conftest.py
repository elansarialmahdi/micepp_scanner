import os
from pathlib import Path

os.environ.update(
    {
        "ENVIRONMENT": "test",
        "DATABASE_URL": "sqlite://",
        "REDIS_URL": "redis://localhost:6399/15",
        "APP_SECRET_KEY": "test-secret-key-with-more-than-thirty-two-characters",
        "AUDIT_HMAC_KEY": "test-audit-key-with-more-than-thirty-two-characters",
        "BOOTSTRAP_ADMIN_USERNAME": "admin",
        "BOOTSTRAP_ADMIN_PASSWORD": "A-Strong-Test-Password-2026!",
    }
)

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.database import Base, SessionLocal, engine
from app.main import app, bootstrap


@pytest.fixture(autouse=True)
def clean_database(tmp_path: Path):
    settings.evidence_root = tmp_path / "evidence"
    settings.work_root = tmp_path / "work"
    settings.report_root = tmp_path / "reports"
    settings.model_root = tmp_path / "models"
    settings.ensure_directories()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    bootstrap()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    with TestClient(app) as value:
        yield value


@pytest.fixture
def token(client: TestClient) -> str:
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "A-Strong-Test-Password-2026!"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture
def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}

