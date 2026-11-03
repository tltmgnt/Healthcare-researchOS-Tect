import io
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tect.models import Claim, Evidence, Relation
from tect.storage import save_claim
from tect.verification_records import record_doi_verification
from tect.composite_object_storage import publish_composite_anchor, retrieve_and_verify_composite_anchor


class FakeStore:
    def __init__(self):
        self.objects = {}

    def put_object(self, *, Bucket, Key, Body, ContentType, IfNoneMatch, Metadata):
        assert IfNoneMatch == "*"
        assert Metadata["sha256"]
        if (Bucket, Key) in self.objects:
            raise FileExistsError()
        self.objects[Bucket, Key] = Body
        return {"VersionId": "v1"}

    def get_object(self, *, Bucket, Key, **kwargs):
        return {"Body": io.BytesIO(self.objects[Bucket, Key])}


@pytest.fixture
def published(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "audit.sqlite3"))
    save_claim(Claim(id="c", text="Synthetic", evidence=[
        Evidence(id="e", source="Fixture", locator="doi:10.1234/test",
                 excerpt="Synthetic", relation=Relation.SUPPORTS)]), expected_version=0)
    record_doi_verification("c", 1, "e", resolver=lambda doi: {"DOI": doi})
    store = FakeStore()
    key = Ed25519PrivateKey.generate()
    info = publish_composite_anchor(store, "audit", "anchors/one.json", key, "key")
    return store, key, info


def check(published):
    store, key, info = published
    return retrieve_and_verify_composite_anchor(store, info["bucket"], info["key"],
                                                {"key": key.public_key()}, expected_sha256=info["sha256"],
                                                version_id=info["version_id"])


def test_roundtrip(published):
    assert check(published)["valid"]


def test_append_only_history(published):
    save_claim(Claim(id="later", text="Synthetic"), expected_version=0)
    assert check(published)["valid"]


def test_duplicate_rejected(published):
    store, key, info = published
    with pytest.raises(FileExistsError):
        publish_composite_anchor(store, info["bucket"], info["key"], key, "key")


def test_tampered_object(published):
    store, _, info = published
    store.objects[info["bucket"], info["key"]] += b"!"
    assert check(published)["reason"] == "object_digest_mismatch"


def test_untrusted_key(published):
    store, _, info = published
    result = retrieve_and_verify_composite_anchor(store, info["bucket"], info["key"], {},
                                                  expected_sha256=info["sha256"])
    assert result["reason"] == "untrusted_key"


def test_invalid_digest(published):
    store, _, info = published
    result = retrieve_and_verify_composite_anchor(store, info["bucket"], info["key"], {},
                                                  expected_sha256="invalid")
    assert result["reason"] == "invalid_expected_digest"


def test_oversized_object(published):
    store, _, info = published
    store.objects[info["bucket"], info["key"]] = b"x" * 65537
    assert check(published)["reason"] == "object_too_large"
