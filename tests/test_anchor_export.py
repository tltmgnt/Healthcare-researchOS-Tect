import json
import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.anchor_export import export_signed_anchor, verify_anchor_file
from tect.models import Claim
from tect.storage import save_claim


@pytest.fixture
def anchor(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "audit.sqlite3"))
    save_claim(Claim(id="one", text="Synthetic"), expected_version=0)
    private = Ed25519PrivateKey.generate()
    path = tmp_path / "anchor.json"
    export_signed_anchor(path, private, "key-1")
    return path, private.public_key()


def test_anchor_roundtrip(anchor):
    path, public = anchor
    assert verify_anchor_file(path, {"key-1": public})["valid"]


def test_anchor_after_append(anchor):
    path, public = anchor
    save_claim(Claim(id="two", text="Synthetic"), expected_version=0)
    assert verify_anchor_file(path, {"key-1": public})["valid"]


def test_anchor_tampering(anchor):
    path, public = anchor
    data = json.loads(path.read_text())
    data["checkpoint"]["head_hash"] = "0" * 64
    path.write_text(json.dumps(data))
    assert verify_anchor_file(path, {"key-1": public})["reason"] == "signature_mismatch"


def test_anchor_cannot_overwrite(anchor):
    path, _ = anchor
    with pytest.raises(FileExistsError):
        export_signed_anchor(path, Ed25519PrivateKey.generate(), "key-2")


def test_anchor_unknown_key(anchor):
    path, _ = anchor
    assert verify_anchor_file(path, {})["reason"] == "untrusted_key"


def test_anchor_missing_file(tmp_path):
    assert verify_anchor_file(tmp_path / "missing.json", {})["reason"] == "unreadable_anchor"


def test_anchor_private_permissions(anchor):
    path, _ = anchor
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0
