import copy
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.ed25519_checkpoints import sign_checkpoint, verify_signed_checkpoint
from tect.models import Claim
from tect.storage import save_claim


@pytest.fixture
def signed(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "audit.sqlite3"))
    save_claim(Claim(id="one", text="Synthetic"), expected_version=0)
    private = Ed25519PrivateKey.generate()
    return sign_checkpoint(private, "audit-1"), private.public_key()


def test_public_key_roundtrip(signed):
    envelope, public = signed
    assert verify_signed_checkpoint(envelope, {"audit-1": public})["valid"]


def test_untrusted_key_rejected(signed):
    envelope, _ = signed
    assert verify_signed_checkpoint(envelope, {})["reason"] == "untrusted_key"


def test_different_public_key_rejected(signed):
    envelope, _ = signed
    other = Ed25519PrivateKey.generate().public_key()
    assert verify_signed_checkpoint(envelope, {"audit-1": other})["reason"] == "signature_mismatch"


def test_modified_checkpoint_rejected(signed):
    envelope, public = signed
    changed = copy.deepcopy(envelope)
    changed["checkpoint"]["head_hash"] = "0" * 64
    assert verify_signed_checkpoint(changed, {"audit-1": public})["reason"] == "signature_mismatch"


def test_malformed_signature_rejected(signed):
    envelope, public = signed
    changed = copy.deepcopy(envelope)
    changed["signature_hex"] = "not-a-signature"
    assert verify_signed_checkpoint(changed, {"audit-1": public})["reason"] == "invalid_signature"


def test_new_event_changes_head(signed):
    envelope, public = signed
    save_claim(Claim(id="two", text="Synthetic"), expected_version=0)
    assert verify_signed_checkpoint(envelope, {"audit-1": public})["reason"] == "head_mismatch"
