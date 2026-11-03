import copy
import pytest

from tect.signed_checkpoints import sign_checkpoint, verify_signed_checkpoint
from tect.models import Claim
from tect.storage import save_claim

KEY = b"synthetic-test-only-secret-32-bytes-minimum"


@pytest.fixture
def checkpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "audit.sqlite3"))
    save_claim(Claim(id="one", text="Synthetic"), expected_version=0)
    return sign_checkpoint(KEY, "test-key")


def test_signed_roundtrip(checkpoint):
    assert verify_signed_checkpoint(checkpoint, {"test-key": KEY})["valid"]


def test_wrong_key_fails(checkpoint):
    assert not verify_signed_checkpoint(checkpoint, {"test-key": b"other-synthetic-secret-32-bytes-minimum"})["valid"]


def test_unknown_key_fails(checkpoint):
    assert verify_signed_checkpoint(checkpoint, {})["reason"] == "unknown_key"


def test_modified_manifest_fails(checkpoint):
    modified = copy.deepcopy(checkpoint)
    modified["checkpoint"]["head_hash"] = "0" * 64
    assert verify_signed_checkpoint(modified, {"test-key": KEY})["reason"] == "signature_mismatch"


def test_modified_key_id_fails(checkpoint):
    modified = copy.deepcopy(checkpoint)
    modified["key_id"] = "other"
    assert not verify_signed_checkpoint(modified, {"test-key": KEY})["valid"]


def test_short_key_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "audit.sqlite3"))
    with pytest.raises(ValueError):
        sign_checkpoint(b"short", "test-key")
