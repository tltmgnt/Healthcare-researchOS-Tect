"""Phase 14: composite signing reads both audit heads from one SQLite snapshot."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tect.composite_anchors import sign_composite_anchor, verify_composite_anchor
from tect.models import Claim, Evidence, Relation
from tect.storage import connect, save_claim, verify_audit_chain
from tect.verification_records import record_doi_verification, verify_doi_verification_log


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "test.sqlite3"))


def test_shared_connection_verifiers():
    save_claim(Claim(id="c", text="Synthetic"), expected_version=0)
    with connect() as db:
        db.execute("BEGIN")
        assert verify_audit_chain(db)["valid"]
        assert verify_doi_verification_log(db)["valid"]
        db.rollback()


def test_signed_heads_match_both_chains():
    save_claim(Claim(id="c", text="Synthetic", evidence=[
        Evidence(id="e", source="Fixture", locator="doi:10.1234/test",
                 excerpt="Synthetic", relation=Relation.SUPPORTS)]), expected_version=0)
    record_doi_verification("c", 1, "e", resolver=lambda doi: {"DOI": doi})
    key = Ed25519PrivateKey.generate()
    envelope = sign_composite_anchor(key, "key")
    assert envelope["claims"]["events_checked"] == 1
    assert envelope["doi_verifications"]["events_checked"] == 1
    assert verify_composite_anchor(envelope, {"key": key.public_key()})["valid"]


def test_corrupt_claim_chain_refuses_signing():
    save_claim(Claim(id="c", text="Synthetic"), expected_version=0)
    with connect() as db:
        db.execute("UPDATE events SET event_hash='bad'")
        db.commit()
    with pytest.raises(ValueError):
        sign_composite_anchor(Ed25519PrivateKey.generate(), "key")
