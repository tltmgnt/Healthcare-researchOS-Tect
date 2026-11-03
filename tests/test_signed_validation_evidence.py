import copy
from datetime import datetime, timezone
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tect.provider_validation import REQUIRED_CONTROLS
from tect.signed_validation_evidence import sign_validation_bundle, verify_validation_bundle

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def signed():
    attestations = {name: {"passed": True, "evidence_reference": "external://evidence/" + name,
                           "reviewer": "independent", "reviewed_at": "2026-01-01T00:00:00Z"}
                    for name in REQUIRED_CONTROLS}
    key = Ed25519PrivateKey.generate()
    bundle = sign_validation_bundle(attestations, key, "reviewer-key", signed_at=NOW)
    return bundle, key


def test_signed_bundle_roundtrip(signed):
    bundle, key = signed
    assert verify_validation_bundle(bundle, {"reviewer-key": key.public_key()})["valid"]


def test_tampered_reference_rejected(signed):
    bundle, key = signed
    tampered = copy.deepcopy(bundle)
    tampered["attestations"]["denied_deletion_test"]["evidence_reference"] = "fake"
    assert verify_validation_bundle(tampered, {"reviewer-key": key.public_key()})["reason"] == "signature_mismatch"


def test_untrusted_key_rejected(signed):
    bundle, _ = signed
    assert verify_validation_bundle(bundle, {})["reason"] == "untrusted_key"


def test_wrong_key_rejected(signed):
    bundle, _ = signed
    wrong = Ed25519PrivateKey.generate().public_key()
    assert verify_validation_bundle(bundle, {"reviewer-key": wrong})["reason"] == "signature_mismatch"


def test_missing_control_refuses_signing(signed):
    bundle, key = signed
    attestations = copy.deepcopy(bundle["attestations"])
    del attestations["denied_deletion_test"]
    with pytest.raises(ValueError):
        sign_validation_bundle(attestations, key, "reviewer-key")


def test_failed_control_refuses_signing(signed):
    bundle, key = signed
    attestations = copy.deepcopy(bundle["attestations"])
    attestations["denied_deletion_test"]["passed"] = False
    with pytest.raises(ValueError):
        sign_validation_bundle(attestations, key, "reviewer-key")


def test_extra_control_refuses_signing(signed):
    bundle, key = signed
    attestations = copy.deepcopy(bundle["attestations"])
    attestations["unknown"] = {"passed": True}
    with pytest.raises(ValueError):
        sign_validation_bundle(attestations, key, "reviewer-key")


def test_invalid_signature_rejected(signed):
    bundle, key = signed
    tampered = {**bundle, "signature_hex": "bad"}
    assert verify_validation_bundle(tampered, {"reviewer-key": key.public_key()})["reason"] == "invalid_signature"


def test_naive_time_rejected(signed):
    bundle, key = signed
    with pytest.raises(ValueError):
        sign_validation_bundle(bundle["attestations"], key, "reviewer-key", signed_at=datetime(2026, 1, 1))
