import io
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tect.models import Claim, Evidence, Relation
from tect.storage import save_claim
from tect.verification_records import record_doi_verification
from tect.composite_object_storage import publish_composite_anchor
from tect.recovery_assurance import audit_composite_anchor_recovery

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Store:
    def __init__(self):
        self.objects = {}
        self.mode = "COMPLIANCE"
        self.days = 500

    def put_object(self, *, Bucket, Key, Body, ContentType, IfNoneMatch, Metadata):
        if (Bucket, Key) in self.objects:
            raise FileExistsError()
        self.objects[Bucket, Key] = Body
        return {"VersionId": "v1"}

    def get_object(self, *, Bucket, Key, VersionId):
        assert VersionId == "v1"
        return {"Body": io.BytesIO(self.objects[Bucket, Key])}

    def get_bucket_versioning(self, *, Bucket):
        return {"Status": "Enabled"}

    def get_object_lock_configuration(self, *, Bucket):
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": self.mode, "Days": self.days}}}}

    def get_object_retention(self, *, Bucket, Key, VersionId):
        return {"Retention": {"Mode": self.mode, "RetainUntilDate": NOW + timedelta(days=self.days)}}


@pytest.fixture
def published(tmp_path, monkeypatch):
    monkeypatch.setenv("TECT_DB_PATH", str(tmp_path / "audit.sqlite3"))
    save_claim(Claim(id="c", text="Synthetic", evidence=[
        Evidence(id="e", source="Fixture", locator="doi:10.1234/test",
                 excerpt="Synthetic", relation=Relation.SUPPORTS)]), expected_version=0)
    record_doi_verification("c", 1, "e", resolver=lambda doi: {"DOI": doi})
    store = Store()
    key = Ed25519PrivateKey.generate()
    info = publish_composite_anchor(store, "audit", "anchors/one.json", key, "key")
    return store, key, info


def audit(published, **overrides):
    store, key, info = published
    args = dict(expected_sha256=info["sha256"], now=NOW)
    args.update(overrides)
    return audit_composite_anchor_recovery(
        store, "audit", "anchors/one.json", "v1", {"key": key.public_key()}, **args)


def test_recovery_passes(published):
    report = audit(published)
    assert report["ready"]
    assert all(report["checks"].values())


def test_append_only_history(published):
    save_claim(Claim(id="later", text="Synthetic"), expected_version=0)
    assert audit(published)["ready"]


def test_wrong_digest_fails(published):
    assert not audit(published, expected_sha256="0" * 64)["ready"]


def test_short_retention_fails(published):
    published[0].days = 30
    report = audit(published)
    assert not report["ready"]
    assert not report["checks"]["object_version_retention"]


def test_governance_mode_fails(published):
    published[0].mode = "GOVERNANCE"
    assert not audit(published)["ready"]


def test_corrupted_object_fails(published):
    store, _, info = published
    store.objects["audit", "anchors/one.json"] += b"x"
    assert not audit(published)["ready"]


def test_invalid_version_rejected(published):
    store, key, info = published
    with pytest.raises(ValueError):
        audit_composite_anchor_recovery(store, "audit", "anchors/one.json", "",
                                        {"key": key.public_key()}, expected_sha256=info["sha256"])


def test_naive_now_rejected(published):
    with pytest.raises(ValueError):
        audit(published, now=datetime(2026, 1, 1))
