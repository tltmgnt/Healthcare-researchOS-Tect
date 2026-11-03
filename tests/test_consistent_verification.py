"""Composite anchor verification must use a shared SQLite snapshot."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.composite_anchors import sign_composite_anchor, verify_composite_anchor
from tect.historical_audit import verify_audit_prefix
from tect.models import Claim, Evidence, Relation
from tect.storage import connect, save_claim
from tect.verification_records import record_doi_verification


@pytest.fixture(autouse=True)
def db_path(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "test.sqlite3"))


def test_historical_prefix_accepts_shared_connection():
    save_claim(Claim(id="c", text="Synthetic"), expected_version=0)
    with connect() as db:
        db.execute("BEGIN")
        row = db.execute("SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        assert verify_audit_prefix(1, row[0], db=db)["valid"]
        db.rollback()


def test_composite_roundtrip_with_appends():
    save_claim(Claim(id="c", text="Synthetic", evidence=[
        Evidence(id="e", source="Fixture", locator="doi:10.1234/test",
                 excerpt="Synthetic", relation=Relation.SUPPORTS)]), expected_version=0)
    record_doi_verification("c", 1, "e", resolver=lambda doi: {"DOI": doi})
    key = Ed25519PrivateKey.generate()
    anchor = sign_composite_anchor(key, "key")
    save_claim(Claim(id="new", text="Synthetic"), expected_version=0)
    record_doi_verification("c", 1, "e", resolver=lambda doi: {"DOI": doi})
    assert verify_composite_anchor(anchor, {"key": key.public_key()})["valid"]


def test_composite_verification_rejects_modified_history():
    save_claim(Claim(id="c", text="Synthetic", evidence=[
        Evidence(id="e", source="Fixture", locator="doi:10.1234/test",
                 excerpt="Synthetic", relation=Relation.SUPPORTS)]), expected_version=0)
    record_doi_verification("c", 1, "e", resolver=lambda doi: {"DOI": doi})
    key = Ed25519PrivateKey.generate()
    anchor = sign_composite_anchor(key, "key")
    with connect() as db:
        db.execute("UPDATE evidence_verification_events SET result_json='{}'")
        db.commit()
    assert verify_composite_anchor(anchor, {"key": key.public_key()})["reason"] == "doi_log_invalid"
