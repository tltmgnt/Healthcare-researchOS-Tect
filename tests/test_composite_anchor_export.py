import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.composite_anchor_export import export_composite_anchor, verify_composite_anchor_file
from tect.models import Claim, Evidence, Relation
from tect.storage import save_claim
from tect.verification_records import record_doi_verification


@pytest.fixture
def anchor(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "audit.sqlite3"))
    save_claim(Claim(id="c", text="Synthetic", evidence=[
        Evidence(id="e", source="Fixture", locator="doi:10.1234/test",
                 excerpt="Synthetic", relation=Relation.SUPPORTS)]), expected_version=0)
    record_doi_verification("c", 1, "e", resolver=lambda doi: {"DOI": doi})
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "composite.json"
    export_composite_anchor(path, key, "key")
    return path, key


def test_roundtrip(anchor):
    path, key = anchor
    assert verify_composite_anchor_file(path, {"key": key.public_key()})["valid"]


def test_refuses_overwrite(anchor):
    path, key = anchor
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        export_composite_anchor(path, key, "key")
    assert path.read_bytes() == original


def test_file_private_permissions(anchor):
    path, _ = anchor
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600


def test_tampering_rejected(anchor):
    path, key = anchor
    path.write_bytes(path.read_bytes().replace(b"crossref", b"modified"))
    # No "crossref" in a composite anchor; explicitly modify a signed field.
    import json
    envelope = json.loads(path.read_text())
    envelope["key_id"] = "altered"
    path.write_text(json.dumps(envelope))
    assert not verify_composite_anchor_file(path, {"key": key.public_key()})["valid"]


def test_untrusted_key(anchor):
    path, _ = anchor
    assert verify_composite_anchor_file(path, {})["reason"] == "untrusted_key"


def test_oversized_file(anchor):
    path, key = anchor
    path.write_bytes(b"x" * 65537)
    assert verify_composite_anchor_file(path, {"key": key.public_key()})["reason"] == "anchor_too_large"


def test_invalid_json(anchor):
    path, key = anchor
    path.write_text("{")
    assert verify_composite_anchor_file(path, {"key": key.public_key()})["reason"] == "unreadable_anchor"
