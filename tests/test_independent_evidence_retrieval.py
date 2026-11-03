import io
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.provider_validation import REQUIRED_CONTROLS
from tect.validation_artifact_manifest import sign_artifact_manifest
from tect.independent_evidence_retrieval import verify_retrieved_evidence


class FakeStore:
    def __init__(self, artifacts):
        self.objects = {("external", control, "v1"): body for control, body in artifacts.items()}
        self.calls = []

    def get_object(self, *, Bucket, Key, VersionId):
        self.calls.append((Bucket, Key, VersionId))
        return {"Body": io.BytesIO(self.objects[Bucket, Key, VersionId])}


@pytest.fixture
def prepared():
    attestations = {name: {"passed": True, "evidence_reference": "external://evidence/" + name,
                           "reviewer": "independent", "reviewed_at": "2026-01-01T00:00:00Z"}
                    for name in REQUIRED_CONTROLS}
    artifacts = {name: ("report:" + name).encode() for name in REQUIRED_CONTROLS}
    key = Ed25519PrivateKey.generate()
    manifest = sign_artifact_manifest(attestations, artifacts, key, "reviewer",
                                      signed_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    store = FakeStore(artifacts)
    locations = {name: {"bucket": "external", "key": name, "version_id": "v1"}
                 for name in REQUIRED_CONTROLS}
    return store, manifest, locations, {"reviewer": key.public_key()}


def check(prepared, **kwargs):
    store, manifest, locations, keys = prepared
    return verify_retrieved_evidence(kwargs.get("store", store), kwargs.get("manifest", manifest),
                                     kwargs.get("locations", locations), kwargs.get("keys", keys))


def test_retrieval_roundtrip(prepared):
    assert check(prepared)["valid"]
    assert len(prepared[0].calls) == 6


def test_tampered_object(prepared):
    prepared[0].objects["external", "denied_deletion_test", "v1"] += b"!"
    assert check(prepared)["reason"] == "artifact_digest_mismatch"


def test_missing_version_rejected_before_reads(prepared):
    locations = {k: dict(v) for k, v in prepared[2].items()}
    locations["denied_deletion_test"]["version_id"] = ""
    assert check(prepared, locations=locations)["reason"] == "invalid_location"
    assert not prepared[0].calls


def test_missing_control_rejected(prepared):
    locations = dict(prepared[2])
    del locations["denied_deletion_test"]
    assert check(prepared, locations=locations)["reason"] == "invalid_locations"


def test_wrong_key_rejected(prepared):
    assert check(prepared, keys={})["reason"] == "validation_bundle_invalid"


def test_provider_error_fails_closed(prepared):
    del prepared[0].objects["external", "denied_deletion_test", "v1"]
    assert check(prepared)["reason"] == "retrieval_failed"


def test_oversized_object_rejected(prepared):
    prepared[0].objects["external", "denied_deletion_test", "v1"] = b"x" * (16 * 1024 * 1024 + 1)
    assert check(prepared)["reason"] == "invalid_retrieved_artifact"


def test_wrong_version_fails_closed(prepared):
    locations = {k: dict(v) for k, v in prepared[2].items()}
    locations["denied_deletion_test"]["version_id"] = "v2"
    assert check(prepared, locations=locations)["reason"] == "retrieval_failed"
