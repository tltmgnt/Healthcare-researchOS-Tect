import copy
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tect.ed25519_checkpoints import sign_checkpoint
from tect.historical_audit import verify_audit_prefix, verify_historical_signed_checkpoint
from tect.models import Claim
from tect.storage import connect, save_claim


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "audit.sqlite3"))
    save_claim(Claim(id="one", text="Synthetic"), expected_version=0)
    key = Ed25519PrivateKey.generate()
    envelope = sign_checkpoint(key, "key-1")
    return envelope, key.public_key()


def test_historical_checkpoint_after_append(setup):
    envelope, public = setup
    save_claim(Claim(id="two", text="Synthetic"), expected_version=0)
    result = verify_historical_signed_checkpoint(envelope, {"key-1": public})
    assert result["valid"] and result["current_events"] == 2


def test_historical_signature_tampering(setup):
    envelope, public = setup
    modified = copy.deepcopy(envelope)
    modified["checkpoint"]["events_checked"] = 0
    assert verify_historical_signed_checkpoint(modified, {"key-1": public})["reason"] == "signature_mismatch"


def test_historical_payload_tampering(setup):
    envelope, public = setup
    save_claim(Claim(id="two", text="Synthetic"), expected_version=0)
    with connect() as db:
        db.execute("UPDATE claims SET payload=? WHERE id=?", ('{"tampered":true}', "two"))
        db.commit()
    assert verify_historical_signed_checkpoint(envelope, {"key-1": public})["reason"] == "audit_chain_invalid"


def test_historical_deleted_event_detected(setup):
    envelope, public = setup
    save_claim(Claim(id="two", text="Synthetic"), expected_version=0)
    with connect() as db:
        db.execute("DELETE FROM events WHERE seq=1")
        db.commit()
    assert verify_historical_signed_checkpoint(envelope, {"key-1": public})["reason"] == "audit_chain_invalid"


def test_prefix_ahead_of_log(setup):
    assert verify_audit_prefix(3, "0" * 64)["reason"] == "checkpoint_ahead_of_log"


def test_wrong_historical_head(setup):
    assert verify_audit_prefix(1, "0" * 64)["reason"] == "historical_head_mismatch"
