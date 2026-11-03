import hashlib
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tect.cloudtrail_digest_preflight import verify_cloudtrail_digest_preflight

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


@pytest.fixture
def sample():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    logs = {"AWSLogs/123/CloudTrail/log.json.gz": b"provider log bytes"}
    manifest = {"logFiles": [{"s3Object": path, "hashAlgorithm": "SHA-256",
                              "hashValue": hashlib.sha256(raw).hexdigest()}
                             for path, raw in logs.items()]}
    digest = json.dumps(manifest).encode()
    message = b"caller-provided-signed-message"
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256()).hex()
    return key, logs, digest, message, signature


def run(s, **overrides):
    key, logs, digest, message, signature = s
    args = dict(signature_hex=signature, signed_message=message,
                trusted_rsa_public_key=key.public_key(),
                expected_digest_sha256=hashlib.sha256(digest).hexdigest(),
                expected_log_paths=set(logs), checked_at=NOW)
    args.update(overrides)
    return verify_cloudtrail_digest_preflight(digest, logs, **args)


def test_valid_preflight(sample):
    assert run(sample)["valid"]


def test_wrong_digest_hash(sample):
    assert run(sample, expected_digest_sha256="0" * 64)["reason"] == "digest_sha256_mismatch"


def test_bad_signature(sample):
    assert run(sample, signature_hex="0" * 512)["reason"] == "rsa_signature_invalid"


def test_different_signed_message(sample):
    assert run(sample, signed_message=b"other")["reason"] == "rsa_signature_invalid"


def test_wrong_key(sample):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert not run(sample, trusted_rsa_public_key=other.public_key())["valid"]


def test_missing_log(sample):
    sample[1].clear()
    assert run(sample, expected_log_paths={"missing"})["reason"] == "log_file_set_mismatch"


def test_tampered_log(sample):
    path = next(iter(sample[1]))
    sample[1][path] = b"altered"
    assert run(sample)["reason"] == "log_hash_mismatch"


def test_extra_log(sample):
    sample[1]["extra"] = b"extra"
    assert run(sample, expected_log_paths={next(iter(sample[1]))})["reason"] == "log_file_set_mismatch"


def test_oversize_digest(sample):
    assert verify_cloudtrail_digest_preflight(b"x" * (2 * 1024 * 1024 + 1), sample[1],
        signature_hex=sample[4], signed_message=sample[3],
        trusted_rsa_public_key=sample[0].public_key(),
        expected_digest_sha256="0" * 64,
        expected_log_paths=set(sample[1]), checked_at=NOW)["reason"] == "invalid_digest_bytes"


def test_invalid_digest_json(sample):
    data = b"not-json"
    assert verify_cloudtrail_digest_preflight(data, sample[1],
        signature_hex=sample[4], signed_message=sample[3],
        trusted_rsa_public_key=sample[0].public_key(),
        expected_digest_sha256=hashlib.sha256(data).hexdigest(),
        expected_log_paths=set(sample[1]), checked_at=NOW)["reason"] == "invalid_digest_json"


def test_weak_key(sample):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    assert run(sample, trusted_rsa_public_key=key.public_key())["reason"] == "untrusted_or_weak_rsa_key"


def test_naive_checked_at(sample):
    with pytest.raises(ValueError):
        run(sample, checked_at=datetime(2026, 11, 3))


def test_invalid_log_manifest(sample):
    data = json.dumps({"logFiles": [{"s3Object": next(iter(sample[1])),
                                     "hashAlgorithm": "MD5", "hashValue": "0" * 64}]}).encode()
    assert verify_cloudtrail_digest_preflight(data, sample[1],
        signature_hex=sample[4], signed_message=sample[3],
        trusted_rsa_public_key=sample[0].public_key(),
        expected_digest_sha256=hashlib.sha256(data).hexdigest(),
        expected_log_paths=set(sample[1]), checked_at=NOW)["reason"] == "unexpected_or_invalid_log_entry"
