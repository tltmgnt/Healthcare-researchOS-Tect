import pytest
from tect.models import Claim, Evidence, Relation
from tect.provenance import verify_provenance
from tect.storage import connect, save_claim, verify_audit_chain
from tect.historical_audit import verify_audit_prefix


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "audit.sqlite3"))


def test_automatic_provenance():
    save_claim(Claim(id="one", text="Synthetic", evidence=[
        Evidence(id="e", source="fixture", locator="fixture:1", excerpt="Synthetic",
                 relation=Relation.SUPPORTS)]), expected_version=0)
    assert verify_provenance("one", 1)["valid"]
    assert verify_audit_chain()["valid"]


def test_missing_provenance_breaks_audit():
    save_claim(Claim(id="one", text="Synthetic"), expected_version=0)
    with connect() as db:
        db.execute("DELETE FROM evidence_provenance")
        db.commit()
    assert not verify_audit_chain()["valid"]
    assert not verify_audit_prefix(1, "0" * 64)["valid"]


def test_modified_provenance_breaks_audit():
    save_claim(Claim(id="one", text="Synthetic"), expected_version=0)
    with connect() as db:
        db.execute("UPDATE evidence_provenance SET manifest_sha256='invalid'")
        db.commit()
    assert not verify_audit_chain()["valid"]


def test_revision_provenance_is_versioned():
    save_claim(Claim(id="one", text="First"), expected_version=0)
    save_claim(Claim(id="one", text="Second"), expected_version=1)
    assert verify_provenance("one", 1)["valid"]
    assert verify_provenance("one", 2)["valid"]
    assert verify_audit_chain()["events_checked"] == 2


def test_failed_revision_does_not_create_provenance():
    save_claim(Claim(id="one", text="First"), expected_version=0)
    with pytest.raises(ValueError):
        save_claim(Claim(id="one", text="Second"), expected_version=0)
    with connect() as db:
        count = db.execute("SELECT COUNT(*) FROM evidence_provenance").fetchone()[0]
    assert count == 1
