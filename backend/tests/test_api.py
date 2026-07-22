from io import BytesIO


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

