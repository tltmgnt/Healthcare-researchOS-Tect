import copy
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.composite_anchors import sign_composite_anchor, verify_composite_anchor
from tect.models import Claim, Evidence, Relation
from tect.storage import connect, save_claim
from tect.verification_records import record_doi_verification


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "test.sqlite3"))
    save_claim(Claim(id="c", text="Synthetic", evidence=[
        Evidence(id="e", source="Fixture", locator="doi:10.1234/test",
                 excerpt="Synthetic", relation=Relation.SUPPORTS)]), expected_version=0)
    record_doi_verification("c", 1, "e", resolver=lambda doi: {"DOI": doi})
    key = Ed25519PrivateKey.generate()
    return key, sign_composite_anchor(key, "audit-key")


def test_composite_roundtrip(fixture):
    key, envelope = fixture
    assert verify_composite_anchor(envelope, {"audit-key": key.public_key()})["valid"]


def test_append_after_signing(fixture):
    key, envelope = fixture
    save_claim(Claim(id="new", text="Synthetic"), expected_version=0)
    record_doi_verification("c", 1, "e", resolver=lambda doi: {"DOI": doi})
    assert verify_composite_anchor(envelope, {"audit-key": key.public_key()})["valid"]


def test_tampered_anchor(fixture):
    key, envelope = fixture
    altered = copy.deepcopy(envelope)
    altered["doi_verifications"]["events_checked"] = 0
    assert verify_composite_anchor(altered, {"audit-key": key.public_key()})["reason"] == "signature_mismatch"


def test_deleted_verification_event(fixture):
    key, envelope = fixture
    with connect() as db:
        db.execute("DELETE FROM evidence_verification_events")
        db.commit()
    assert verify_composite_anchor(envelope, {"audit-key": key.public_key()})["reason"] == "doi_prefix_mismatch"


def test_modified_verification_event(fixture):
    key, envelope = fixture
    with connect() as db:
        db.execute("UPDATE evidence_verification_events SET result_json='{}'")
        db.commit()
    assert verify_composite_anchor(envelope, {"audit-key": key.public_key()})["reason"] == "doi_log_invalid"


def test_untrusted_key(fixture):
    _, envelope = fixture
    assert verify_composite_anchor(envelope, {})["reason"] == "untrusted_key"


def test_refuses_corrupted_log(fixture):
    key, _ = fixture
    with connect() as db:
        db.execute("UPDATE evidence_verification_events SET event_hash='invalid'")
        db.commit()
    with pytest.raises(ValueError):
        sign_composite_anchor(key, "audit-key")
