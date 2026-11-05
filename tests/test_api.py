import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from cloudposture.api import create_app
from cloudposture.db import Base


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    app = create_app(
        session_factory=factory,
        api_keys={"admin-key": "admin", "analyst-key": "analyst", "viewer-key": "viewer"},
        init_database=False,
    )
    return TestClient(app)


def test_api_requires_auth(client):
    assert client.get("/summary").status_code == 401
    assert client.post("/accounts", json={"provider": "aws", "account_id": "1", "name": "x"}, headers={"X-API-Key": "viewer-key"}).status_code == 403


def test_api_full_posture_flow(client):
    admin = {"X-API-Key": "admin-key"}
    analyst = {"X-API-Key": "analyst-key"}
    viewer = {"X-API-Key": "viewer-key"}
    account = client.post("/accounts", json={"provider": "aws", "account_id": "123", "name": "prod"}, headers=admin)
    assert account.status_code == 200
    account_id = account.json()["id"]

    sync = client.post(
        f"/accounts/{account_id}/sync",
        json={"resources": [{"resource_id": "bucket-1", "resource_type": "s3_bucket", "config": {"public": True, "encrypted": False}, "tags": {"owner": "platform", "environment": "prod"}}]},
        headers=analyst,
    )
    assert sync.status_code == 200

    findings = client.get("/findings", headers=viewer)
    assert findings.status_code == 200
    assert len(findings.json()["findings"]) == 2
    finding_id = findings.json()["findings"][0]["id"]

    resolve = client.post(f"/findings/{finding_id}/resolve", json={"note": "Blocked public access"}, headers=analyst)
    assert resolve.status_code == 200
    assert resolve.json()["status"] == "resolved"

    summary = client.get("/summary", headers=viewer)
    assert summary.status_code == 200
    assert summary.json()["open_findings"] == 1


def test_api_validation_and_not_found(client):
    admin = {"X-API-Key": "admin-key"}
    bad = client.post("/accounts", json={"provider": "oracle", "account_id": "1", "name": "x"}, headers=admin)
    assert bad.status_code == 422
    missing = client.post("/accounts/999/sync", json={"resources": []}, headers={"X-API-Key": "analyst-key"})
    assert missing.status_code == 404
