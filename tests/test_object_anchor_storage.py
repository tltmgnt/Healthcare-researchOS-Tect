import copy
import hashlib
import io
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.ed25519_checkpoints import sign_checkpoint
from tect.object_anchor_storage import publish_anchor, retrieve_and_verify_anchor
from tect.models import Claim
from tect.storage import save_claim


class FakeObjectStore:
    def __init__(self):
        self.objects = {}

    def put_object(self, *, Bucket, Key, Body, ContentType, IfNoneMatch, Metadata):
        assert IfNoneMatch == "*"
        if (Bucket, Key) in self.objects:
            raise FileExistsError("object already exists")
        self.objects[Bucket, Key] = Body
        return {"VersionId": "v1"}

    def get_object(self, *, Bucket, Key, **kwargs):
        return {"Body": io.BytesIO(self.objects[Bucket, Key])}


@pytest.fixture
def anchored(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "audit.sqlite3"))
    save_claim(Claim(id="one", text="Synthetic"), expected_version=0)
    key = Ed25519PrivateKey.generate()
    envelope = sign_checkpoint(key, "test")
    client = FakeObjectStore()
    published = publish_anchor(client, "audit-bucket", "anchors/one.json", envelope)
    return client, published, key.public_key(), envelope


def test_publish_retrieve_verify(anchored):
    client, info, public, _ = anchored
    assert retrieve_and_verify_anchor(client, info["bucket"], info["key"], {"test": public},
                                      expected_sha256=info["sha256"], version_id=info["version_id"])["valid"]


def test_object_digest_tampering(anchored):
    client, info, public, _ = anchored
    client.objects[info["bucket"], info["key"]] += b"x"
    assert retrieve_and_verify_anchor(client, info["bucket"], info["key"], {"test": public},
                                      expected_sha256=info["sha256"])["reason"] == "object_digest_mismatch"


def test_duplicate_key_rejected(anchored):
    client, info, _, envelope = anchored
    with pytest.raises(FileExistsError):
        publish_anchor(client, info["bucket"], info["key"], envelope)


def test_wrong_public_key_rejected(anchored):
    client, info, _, _ = anchored
    other = Ed25519PrivateKey.generate().public_key()
    assert retrieve_and_verify_anchor(client, info["bucket"], info["key"], {"test": other},
                                      expected_sha256=info["sha256"])["reason"] == "signature_mismatch"


def test_missing_digest_rejected(anchored):
    client, info, public, _ = anchored
    assert retrieve_and_verify_anchor(client, info["bucket"], info["key"], {"test": public},
                                      expected_sha256="bad")["reason"] == "invalid_expected_digest"


def test_historical_after_append(anchored):
    client, info, public, _ = anchored
    save_claim(Claim(id="two", text="Synthetic"), expected_version=0)
    assert retrieve_and_verify_anchor(client, info["bucket"], info["key"], {"test": public},
                                      expected_sha256=info["sha256"])["valid"]
