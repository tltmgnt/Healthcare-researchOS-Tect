import sqlite3
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from tect.api import app
from tect.models import Claim, Evidence, Relation
from tect.storage import load_claim, save_claim, verify_audit_chain


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "test.sqlite3"))


def test_versions_and_provenance():
    initial = Claim(id="a", text="Synthetic finding")
    assert save_claim(initial, expected_version=0) == 1
    revised = Claim(id="a", text="Revised synthetic finding", evidence=[
        Evidence(id="e", source="fixture", locator="fixture:1",
                 excerpt="Synthetic", relation=Relation.SUPPORTS, verified=False)
    ])
    assert save_claim(revised, expected_version=1) == 2
    assert load_claim("a", 1).text == "Synthetic finding"
    assert load_claim("a").text == "Revised synthetic finding"
    assert verify_audit_chain()["valid"] is True
    with pytest.raises(ValueError):
        save_claim(revised, expected_version=1)


def test_tamper_detected():
    save_claim(Claim(id="a", text="Original"), expected_version=0)
    from tect.storage import database_path
    with sqlite3.connect(database_path()) as db:
        db.execute("UPDATE claims SET payload=? WHERE id='a'", ('{"id":"a","text":"Changed","evidence":[]}',))
    assert verify_audit_chain()["valid"] is False


def test_api_revision_and_audit(monkeypatch):
    token = "synthetic-test-admin-token"
    digest = hashlib.sha256(token.encode()).hexdigest()
    monkeypatch.setenv("TECT_API_KEYS_JSON", json.dumps({digest: "admin"}))
    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {token}"})
    assert client.post("/claims", json={"id": "x", "text": "First"}).status_code == 201
    assert client.post("/claims", json={"id": "x", "text": "Duplicate"}).status_code == 409
    response = client.put("/claims/x", json={"claim": {"id": "x", "text": "Second"}, "expected_version": 1})
    assert response.status_code == 200
    assert client.get("/claims/x/versions").json() == [1, 2]
    assert client.get("/claims/x?version=1").json()["text"] == "First"
    assert client.get("/audit/verify").json()["valid"] is True
