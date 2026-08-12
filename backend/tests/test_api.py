from io import BytesIO

import pytest

from app.config import settings
from app.worker import celery_app


def test_case_evidence_and_integrity_flow(client, auth_headers):
    created = client.post(
        "/api/v1/cases",
        headers=auth_headers,
        json={
            "reference": "AFF-2026-001",
            "title": "Analyse d'un support saisi",
            "description": "Test du flux de conservation",
            "classification": "Confidentiel",
        },
    )
    assert created.status_code == 201
    case_id = created.json()["id"]

    payload = b"contenu de preuve stable\x00" * 128
    uploaded = client.post(
        "/api/v1/evidence",
        headers=auth_headers,
        data={
            "case_id": case_id,
            "label": "Scellé USB 01",
            "kind": "file",
            "acquisition_notes": "Acquis via bloqueur d'écriture",
            "source_identifier": "SC-001",
        },
        files={"file": ("preuve.bin", BytesIO(payload), "application/octet-stream")},
    )
    assert uploaded.status_code == 201, uploaded.text
    evidence = uploaded.json()
    assert evidence["size_bytes"] == len(payload)
    assert len(evidence["sha256"]) == 64

    verified = client.post(f"/api/v1/evidence/{evidence['id']}/verify", headers=auth_headers)
    assert verified.status_code == 200
    assert verified.json()["status"] == "verified"

    audit = client.get("/api/v1/audit/verify", headers=auth_headers)
    assert audit.status_code == 200
    assert audit.json()["valid"] is True


def test_duplicate_case_reference_is_rejected(client, auth_headers):
    body = {"reference": "DUP-1", "title": "Premier dossier"}
    assert client.post("/api/v1/cases", headers=auth_headers, json=body).status_code == 201
    response = client.post("/api/v1/cases", headers=auth_headers, json=body)
    assert response.status_code == 409


def test_reviewer_or_admin_can_seal_case(client, auth_headers):
    created = client.post(
        "/api/v1/cases",
        headers=auth_headers,
        json={"reference": "SEAL-1", "title": "Seal case"},
    )
    assert created.status_code == 201

    sealed = client.post(f"/api/v1/cases/{created.json()['id']}/seal", headers=auth_headers)
    assert sealed.status_code == 200
    assert sealed.json()["status"] == "sealed"


def test_failed_evidence_transaction_removes_stored_original(client, auth_headers, monkeypatch):
    case = client.post(
        "/api/v1/cases",
        headers=auth_headers,
        json={"reference": "ROLLBACK-1", "title": "Rollback upload"},
    )
    assert case.status_code == 201

    def fail_audit(*args, **kwargs):
        raise RuntimeError("simulated audit failure")

    monkeypatch.setattr("app.api.append_event", fail_audit)
    with pytest.raises(RuntimeError, match="simulated audit failure"):
        client.post(
            "/api/v1/evidence",
            headers=auth_headers,
            data={"case_id": case.json()["id"], "label": "Unrecorded evidence", "kind": "file"},
            files={"file": ("evidence.bin", BytesIO(b"original"), "application/octet-stream")},
        )

    assert list(settings.evidence_root.iterdir()) == []


def test_queued_analysis_completes_through_celery(client, auth_headers, monkeypatch):
    monkeypatch.setitem(celery_app.conf, "task_always_eager", True)
    monkeypatch.setitem(celery_app.conf, "task_eager_propagates", True)
    case = client.post(
        "/api/v1/cases",
        headers=auth_headers,
        json={"reference": "E2E-ANALYSIS-1", "title": "Celery analysis"},
    )
    assert case.status_code == 201
    uploaded = client.post(
        "/api/v1/evidence",
        headers=auth_headers,
        data={"case_id": case.json()["id"], "label": "Analysis sample", "kind": "file"},
        files={"file": ("sample.txt", BytesIO(b"harmless forensic test content"), "text/plain")},
    )
    assert uploaded.status_code == 201

    queued = client.post(f"/api/v1/evidence/{uploaded.json()['id']}/analyze", headers=auth_headers)
    assert queued.status_code == 202, queued.text

    job = client.get(f"/api/v1/jobs/{queued.json()['id']}", headers=auth_headers)
    assert job.status_code == 200
    assert job.json()["status"] == "awaiting_review"
    assert job.json()["verdict"] == "benign"
    assert job.json()["risk_score"] == 0.0
    assert job.json()["summary"]["artifacts_analyzed"] == 1
    assert job.json()["summary"]["risk_components"] == {
        "static": 0.0,
        "machine_learning": None,
        "sandbox": None,
    }
    assert job.json()["summary"]["dominant_risk_signal"] == "static"


def test_sensitive_routes_require_authentication(client):
    assert client.get("/api/v1/dashboard").status_code == 401
    assert client.get("/api/v1/cases").status_code == 401
    assert client.get("/api/v1/audit/verify").status_code == 401


def test_analyst_cannot_access_reviewer_or_admin_actions(client, auth_headers):
    created = client.post(
        "/api/v1/users",
        headers=auth_headers,
        json={
            "username": "analyst.user",
            "full_name": "Analyst User",
            "password": "A-Strong-Analyst-Password-2026!",
            "role": "analyst",
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/v1/auth/token",
        data={"username": "analyst.user", "password": "A-Strong-Analyst-Password-2026!"},
    )
    analyst_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    assert client.get("/api/v1/audit/verify", headers=analyst_headers).status_code == 403
    assert client.get("/api/v1/users", headers=analyst_headers).status_code == 403
    assert client.post("/api/v1/models/train", headers=analyst_headers).status_code == 403

