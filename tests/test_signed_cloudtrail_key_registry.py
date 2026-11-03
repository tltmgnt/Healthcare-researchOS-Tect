from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from tect.cloudtrail_key_trust import SCHEMA as KEY_SCHEMA, rsa_spki_fingerprint
from tect.signed_cloudtrail_key_registry import (
    sign_cloudtrail_key_registry, verify_signed_cloudtrail_key_registry,
    verify_cloudtrail_key_with_signed_registry
)

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


@pytest.fixture
def sample():
    authority = ed25519.Ed25519PrivateKey.generate()
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    registry = {"schema": KEY_SCHEMA, "sequence": 5, "keys": {
        "aws-key": {"fingerprint_sha256": rsa_spki_fingerprint(signing_key.public_key()),
                    "regions": ["us-west-2"], "accounts": ["123456789012"],
                    "valid_from": (NOW - timedelta(days=1)).isoformat(),
                    "valid_until": (NOW + timedelta(days=1)).isoformat(),
                    "revoked": False, "provenance_reference": "independent-review"}}}
    return authority, signing_key, registry


def sign(sample):
    return sign_cloudtrail_key_registry(
        sample[2], authority_key_id="independent-root",
        authority_private_key=sample[0])


def verify(sample, envelope=None, **overrides):
    args = dict(minimum_sequence=5)
    args.update(overrides)
    return verify_signed_cloudtrail_key_registry(
        envelope if envelope is not None else sign(sample),
        {"independent-root": sample[0].public_key()}, **args)


def test_valid_signed_registry(sample):
    assert verify(sample)["valid"]


def test_sequence_floor(sample):
    assert verify(sample, minimum_sequence=6)["reason"] == "registry_rollback"


def test_tampered_fingerprint(sample):
    envelope = sign(sample)
    envelope["payload"]["registry"]["keys"]["aws-key"]["fingerprint_sha256"] = "0" * 64
    assert verify(sample, envelope)["reason"] == "signature_invalid"


def test_tampered_revocation(sample):
    envelope = sign(sample)
    envelope["payload"]["registry"]["keys"]["aws-key"]["revoked"] = True
    assert verify(sample, envelope)["reason"] == "signature_invalid"


def test_unknown_authority(sample):
    envelope = sign(sample)
    assert not verify_signed_cloudtrail_key_registry(envelope, {}, minimum_sequence=5)["valid"]


def test_wrong_authority_key(sample):
    other = ed25519.Ed25519PrivateKey.generate()
    envelope = sign(sample)
    assert not verify_signed_cloudtrail_key_registry(
        envelope, {"independent-root": other.public_key()}, minimum_sequence=5)["valid"]


def test_invalid_signature(sample):
    envelope = sign(sample)
    envelope["signature_hex"] = "0" * 128
    assert verify(sample, envelope)["reason"] == "signature_invalid"


def test_invalid_registry(sample):
    sample[2]["sequence"] = 0
    with pytest.raises(ValueError):
        sign(sample)


def test_invalid_authority_id(sample):
    with pytest.raises(ValueError):
        sign_cloudtrail_key_registry(sample[2], authority_key_id="",
                                     authority_private_key=sample[0])


def test_unsigned_extra_field(sample):
    envelope = sign(sample)
    envelope["extra"] = "untrusted"
    assert verify(sample, envelope)["reason"] == "invalid_envelope"


def test_valid_scoped_key(sample):
    result = verify_cloudtrail_key_with_signed_registry(
        sample[1].public_key(), sign(sample),
        {"independent-root": sample[0].public_key()},
        minimum_sequence=5, key_id="aws-key", region="us-west-2",
        account_id="123456789012", checked_at=NOW)
    assert result["trusted"]


def test_wrong_scoped_account(sample):
    result = verify_cloudtrail_key_with_signed_registry(
        sample[1].public_key(), sign(sample),
        {"independent-root": sample[0].public_key()},
        minimum_sequence=5, key_id="aws-key", region="us-west-2",
        account_id="000000000000", checked_at=NOW)
    assert result["reason"] == "account_not_approved"


def test_revoked_signed_key(sample):
    sample[2]["keys"]["aws-key"]["revoked"] = True
    result = verify_cloudtrail_key_with_signed_registry(
        sample[1].public_key(), sign(sample),
        {"independent-root": sample[0].public_key()},
        minimum_sequence=5, key_id="aws-key", region="us-west-2",
        account_id="123456789012", checked_at=NOW)
    assert result["reason"] == "key_revoked"


def test_invalid_sequence_policy(sample):
    with pytest.raises(ValueError):
        verify(sample, minimum_sequence=0)
