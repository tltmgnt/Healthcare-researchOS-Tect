from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tect.cloudtrail_key_trust import (
    SCHEMA, rsa_spki_fingerprint, verify_cloudtrail_key_trust,
    verify_pinned_cloudtrail_signature
)

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


@pytest.fixture
def sample():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    registry = {"schema": SCHEMA, "sequence": 5, "keys": {
        "key-1": {"fingerprint_sha256": rsa_spki_fingerprint(key.public_key()),
                  "regions": ["us-west-2"], "accounts": ["123456789012"],
                  "valid_from": (NOW - timedelta(days=1)).isoformat(),
                  "valid_until": (NOW + timedelta(days=1)).isoformat(),
                  "revoked": False, "provenance_reference": "reviewed-key-record"}}}
    return key, registry


def check(sample, **overrides):
    key, registry = sample
    args = dict(key_id="key-1", region="us-west-2", account_id="123456789012",
                checked_at=NOW, expected_registry_sequence=5)
    args.update(overrides)
    return verify_cloudtrail_key_trust(key.public_key(), registry, **args)


def test_valid_key(sample):
    assert check(sample)["trusted"]


def test_rollback(sample):
    assert check(sample, expected_registry_sequence=6)["reason"] == "registry_rollback"


def test_unknown_key(sample):
    assert check(sample, key_id="unknown")["reason"] == "unknown_key"


def test_wrong_region(sample):
    assert check(sample, region="us-east-1")["reason"] == "region_not_approved"


def test_wrong_account(sample):
    assert check(sample, account_id="000000000000")["reason"] == "account_not_approved"


def test_revoked(sample):
    sample[1]["keys"]["key-1"]["revoked"] = True
    assert check(sample)["reason"] == "key_revoked"


def test_expired(sample):
    assert check(sample, checked_at=NOW + timedelta(days=2))["reason"] == "key_outside_validity"


def test_fingerprint_mismatch(sample):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert verify_cloudtrail_key_trust(
        other.public_key(), sample[1], key_id="key-1", region="us-west-2",
        account_id="123456789012", checked_at=NOW,
        expected_registry_sequence=5)["reason"] == "key_fingerprint_mismatch"


def test_missing_provenance(sample):
    sample[1]["keys"]["key-1"]["provenance_reference"] = ""
    assert check(sample)["reason"] == "missing_key_provenance"


def test_invalid_registry(sample):
    sample[1]["extra"] = "unreviewed"
    assert check(sample)["reason"] == "invalid_registry"


def test_valid_signature(sample):
    key, registry = sample
    message = b"caller-provided-message"
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256()).hex()
    result = verify_pinned_cloudtrail_signature(
        key.public_key(), registry, key_id="key-1", region="us-west-2",
        account_id="123456789012", checked_at=NOW,
        expected_registry_sequence=5, signed_message=message,
        signature_hex=signature)
    assert result["signature_valid"]


def test_invalid_signature(sample):
    key, registry = sample
    result = verify_pinned_cloudtrail_signature(
        key.public_key(), registry, key_id="key-1", region="us-west-2",
        account_id="123456789012", checked_at=NOW,
        expected_registry_sequence=5, signed_message=b"message",
        signature_hex="0" * 512)
    assert result["reason"] == "signature_invalid"


def test_naive_checked_at(sample):
    with pytest.raises(ValueError):
        check(sample, checked_at=datetime(2026, 11, 3))


def test_weak_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(ValueError):
        rsa_spki_fingerprint(key.public_key())
