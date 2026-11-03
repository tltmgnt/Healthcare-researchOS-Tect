import copy
from datetime import datetime, timezone
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tect.provider_validation import REQUIRED_CONTROLS
from tect.validation_artifact_manifest import sign_artifact_manifest, verify_artifact_manifest

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def prepared():
    attestations = {name: {"passed": True, "evidence_reference": "external://evidence/" + name,
                           "reviewer": "independent", "reviewed_at": "2026-01-01T00:00:00Z"}
                    for name in REQUIRED_CONTROLS}
    artifacts = {name: ("report:" + name).encode() for name in REQUIRED_CONTROLS}
    key = Ed25519PrivateKey.generate()
    manifest = sign_artifact_manifest(attestations, artifacts, key, "reviewer", signed_at=NOW)
    return manifest, artifacts, key


def verify(prepared, manifest=None, artifacts=None, keys=None):
    original, bodies, key = prepared
    return verify_artifact_manifest(manifest if manifest is not None else original,
                                    artifacts if artifacts is not None else bodies,
                                    keys if keys is not None else {"reviewer": key.public_key()})


def test_roundtrip(prepared):
    assert verify(prepared)["valid"]


def test_changed_artifact_rejected(prepared):
    _, bodies, _ = prepared
    changed = dict(bodies)
    changed["denied_deletion_test"] += b"!"
    assert verify(prepared, artifacts=changed)["reason"] == "artifact_digest_mismatch"


def test_missing_artifact_rejected(prepared):
    _, bodies, _ = prepared
    changed = dict(bodies)
    del changed["denied_deletion_test"]
    assert verify(prepared, artifacts=changed)["reason"] == "missing_or_extra_artifacts"


def test_tampered_digest_rejected(prepared):
    manifest = copy.deepcopy(prepared[0])
    manifest["artifacts"]["denied_deletion_test"]["sha256"] = "0" * 64
    assert verify(prepared, manifest=manifest)["reason"] == "signature_mismatch"


def test_tampered_reference_rejected(prepared):
    manifest = copy.deepcopy(prepared[0])
    manifest["artifacts"]["denied_deletion_test"]["evidence_reference"] = "changed"
    assert verify(prepared, manifest=manifest)["reason"] == "invalid_manifest"


def test_untrusted_reviewer_rejected(prepared):
    assert verify(prepared, keys={})["reason"] == "validation_bundle_invalid"


def test_wrong_reviewer_key_rejected(prepared):
    other = Ed25519PrivateKey.generate().public_key()
    assert verify(prepared, keys={"reviewer": other})["reason"] == "validation_bundle_invalid"


def test_empty_artifact_refuses_signing(prepared):
    manifest, bodies, key = prepared
    changed = dict(bodies)
    changed["denied_deletion_test"] = b""
    with pytest.raises(ValueError):
        sign_artifact_manifest(manifest["validation_bundle"]["attestations"], changed, key, "reviewer")


def test_missing_artifact_refuses_signing(prepared):
    manifest, bodies, key = prepared
    changed = dict(bodies)
    del changed["denied_deletion_test"]
    with pytest.raises(ValueError):
        sign_artifact_manifest(manifest["validation_bundle"]["attestations"], changed, key, "reviewer")


def test_oversized_artifact_refuses_signing(prepared):
    manifest, bodies, key = prepared
    changed = dict(bodies)
    changed["denied_deletion_test"] = b"x" * (16 * 1024 * 1024 + 1)
    with pytest.raises(ValueError):
        sign_artifact_manifest(manifest["validation_bundle"]["attestations"], changed, key, "reviewer")
