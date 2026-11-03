import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.independent_custody_evidence import (
    CONTROLS, SCHEMA, sign_custody_assessment, verify_custody_assessment
)

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


@pytest.fixture
def sample():
    key = Ed25519PrivateKey.generate()
    artifacts = {c: ("evidence:" + c).encode() for c in CONTROLS}
    payload = {
        "schema": SCHEMA, "assessor_key_id": "external-auditor",
        "assessor_id": "external-security", "operator_id": "operations",
        "approved_account_id": "123456789012", "bucket": "independent-anchor-bucket",
        "key": "registry/floor.json", "version_id": "v1",
        "approval_reference": "CAB-123", "assessed_at": NOW.isoformat(),
        "controls": {c: {"passed": True, "reference": "evidence://" + c,
                         "sha256": hashlib.sha256(artifacts[c]).hexdigest()}
                     for c in CONTROLS}}
    return key, payload, artifacts


def sign(sample):
    key, payload, artifacts = sample
    return sign_custody_assessment(payload, artifacts, assessor_private_key=key, checked_at=NOW)


def verify(sample, envelope=None, **overrides):
    key, payload, artifacts = sample
    args = dict(expected_account_id="123456789012",
                expected_bucket="independent-anchor-bucket",
                expected_key="registry/floor.json", expected_version_id="v1",
                expected_operator_id="operations", checked_at=NOW)
    args.update(overrides)
    return verify_custody_assessment(envelope or sign(sample), artifacts,
                                     {"external-auditor": key.public_key()}, **args)


def test_valid_assessment(sample):
    assert verify(sample)["valid"]


def test_tampered_artifact(sample):
    envelope = sign(sample)
    sample[2]["protected_version_deletion_denied"] = b"tampered"
    assert verify(sample, envelope)["reason"] == "artifact_digest_mismatch"


def test_tampered_signed_target(sample):
    envelope = sign(sample)
    envelope["payload"]["bucket"] = "other"
    assert not verify(sample, envelope)["valid"]


def test_wrong_expected_account(sample):
    assert verify(sample, expected_account_id="000000000000")["reason"] == "target_or_operator_mismatch"


def test_wrong_version(sample):
    assert verify(sample, expected_version_id="v2")["reason"] == "target_or_operator_mismatch"


def test_missing_control(sample):
    sample[1]["controls"].pop(CONTROLS[0])
    with pytest.raises(ValueError):
        sign(sample)


def test_failed_control(sample):
    sample[1]["controls"][CONTROLS[0]]["passed"] = False
    with pytest.raises(ValueError):
        sign(sample)


def test_same_assessor_and_operator(sample):
    sample[1]["assessor_id"] = "operations"
    with pytest.raises(ValueError):
        sign(sample)


def test_future_assessment(sample):
    sample[1]["assessed_at"] = (NOW + timedelta(days=1)).isoformat()
    with pytest.raises(ValueError):
        sign(sample)


def test_stale_assessment(sample):
    sample[1]["assessed_at"] = (NOW - timedelta(days=100)).isoformat()
    with pytest.raises(ValueError):
        sign(sample)


def test_unknown_assessor(sample):
    envelope = sign(sample)
    assert not verify_custody_assessment(
        envelope, sample[2], {}, expected_account_id="123456789012",
        expected_bucket="independent-anchor-bucket", expected_key="registry/floor.json",
        expected_version_id="v1", expected_operator_id="operations",
        checked_at=NOW)["valid"]


def test_invalid_signature(sample):
    envelope = sign(sample)
    envelope["signature_hex"] = "0" * 128
    assert verify(sample, envelope)["reason"] == "signature_invalid"


def test_unexpected_artifact(sample):
    sample[2]["extra"] = b"unreviewed"
    with pytest.raises(ValueError):
        sign(sample)
