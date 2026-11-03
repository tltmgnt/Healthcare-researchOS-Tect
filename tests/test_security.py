import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from tect.api import app


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "security.sqlite3"))
    tokens = {
        "reader-secret": "reader",
        "writer-secret": "writer",
        "auditor-secret": "auditor",
        "admin-secret": "admin",
    }
    monkeypatch.setenv("TECT_API_KEYS_JSON", json.dumps({
        hashlib.sha256(token.encode()).hexdigest(): role for token, role in tokens.items()
    }))
    return TestClient(app)


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_missing_and_invalid_credentials(client):
    assert client.get("/claims/demo").status_code == 401
    assert client.get("/claims/demo", headers=headers("wrong")).status_code == 401
    assert client.post("/claims", json={"id": "a", "text": "x"}).status_code == 401
    assert client.get("/health").status_code == 200


def test_role_permissions(client):
    payload = {"id": "demo", "text": "Synthetic claim"}
    assert client.post("/claims", json=payload, headers=headers("reader-secret")).status_code == 403
    assert client.post("/claims", json=payload, headers=headers("writer-secret")).status_code == 201
    assert client.get("/claims/demo", headers=headers("reader-secret")).status_code == 200
    assert client.get("/audit/verify", headers=headers("reader-secret")).status_code == 403
    assert client.get("/audit/verify", headers=headers("writer-secret")).status_code == 403
    assert client.get("/audit/verify", headers=headers("auditor-secret")).status_code == 200
    assert client.post("/claims", json={"id": "b", "text": "x"}, headers=headers("auditor-secret")).status_code == 403
    assert client.get("/audit/verify", headers=headers("admin-secret")).status_code == 200


def test_write_requires_writer_or_admin(client):
    payload = {"id": "demo", "text": "Original"}
    assert client.post("/claims", json=payload, headers=headers("admin-secret")).status_code == 201
    revision = {"claim": {"id": "demo", "text": "Revised"}, "expected_version": 1}
    assert client.put("/claims/demo", json=revision, headers=headers("reader-secret")).status_code == 403
    assert client.put("/claims/demo", json=revision, headers=headers("writer-secret")).status_code == 200
    assert client.get("/claims/demo/versions", headers=headers("reader-secret")).json() == [1, 2]


def test_missing_configuration_fails_closed(client, monkeypatch):
    monkeypatch.delenv("TECT_API_KEYS_JSON")
    assert client.get("/claims/demo", headers=headers("reader-secret")).status_code == 503
    assert client.post("/claims", json={"id": "x", "text": "x"}, headers=headers("writer-secret")).status_code == 503


def test_malformed_configuration_fails_closed(client, monkeypatch):
    monkeypatch.setenv("TECT_API_KEYS_JSON", '{"plaintext":"admin"}')
    assert client.get("/audit/verify", headers=headers("admin-secret")).status_code == 503
