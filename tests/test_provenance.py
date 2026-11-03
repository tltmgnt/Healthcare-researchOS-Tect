import pytest
from tect.models import Claim, Evidence, Relation
from tect.provenance import capture_provenance, verify_provenance
from tect.storage import connect, save_claim


@pytest.fixture
def recorded(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "claims.sqlite3"))
    claim = Claim(id="synthetic", text="Synthetic claim", evidence=[
        Evidence(id="e1", source="Synthetic journal", locator="doi:example",
                 excerpt="Synthetic excerpt", relation=Relation.SUPPORTS)
    ])
    save_claim(claim, expected_version=0)
    return claim


def test_capture_and_verify(recorded):
    manifest = capture_provenance(recorded.id, 1)
    assert manifest["evidence"][0]["locator"] == "doi:example"
    assert verify_provenance(recorded.id, 1)["valid"]


def test_capture_idempotent(recorded):
    assert capture_provenance(recorded.id, 1) == capture_provenance(recorded.id, 1)


def test_missing_version(recorded):
    with pytest.raises(ValueError):
        capture_provenance(recorded.id, 2)


def test_missing_provenance(recorded):
    assert verify_provenance(recorded.id, 1)["reason"] == "missing_provenance_or_claim"


def test_tampered_provenance(recorded):
    capture_provenance(recorded.id, 1)
    with connect() as db:
        db.execute("UPDATE evidence_provenance SET manifest=? WHERE claim_id=?", ('{}', recorded.id))
        db.commit()
    assert verify_provenance(recorded.id, 1)["reason"] == "provenance_mismatch"


def test_tampered_claim(recorded):
    capture_provenance(recorded.id, 1)
    with connect() as db:
        db.execute("UPDATE claims SET payload=? WHERE id=?", ('{"tampered":true}', recorded.id))
        db.commit()
    assert verify_provenance(recorded.id, 1)["reason"] == "provenance_mismatch"
