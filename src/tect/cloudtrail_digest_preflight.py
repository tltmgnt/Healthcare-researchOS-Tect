"""Offline CloudTrail digest integrity and RSA signature preflight.

IMPORTANT: This is not a complete AWS CloudTrail digest signature
verifier. AWS canonical signature-message construction, digest-chain
continuity, key discovery and provenance must be verified independently.
"""
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SCHEMA = "tect.cloudtrail-digest-preflight.v1"
MAX_DIGEST_BYTES = 2 * 1024 * 1024
MAX_LOG_BYTES = 8 * 1024 * 1024
SHA = re.compile(r"^[0-9a-f]{64}$")


def verify_cloudtrail_digest_preflight(digest_bytes: bytes, log_files: dict,
                                       *, signature_hex: str,
                                       signed_message: bytes,
                                       trusted_rsa_public_key: rsa.RSAPublicKey,
                                       expected_digest_sha256: str,
                                       expected_log_paths: set[str],
                                       checked_at: datetime,
                                       max_age_days: int = 90) -> dict:
    """Verify pinned bytes, RSA signature over supplied message, and log hashes.

    The signed message must be constructed and authenticated according to
    the official AWS CloudTrail signature specification by a separate
    trusted integration. Caller-supplied message is NOT reconstructed here.
    """
    def denied(reason):
        return {"schema": SCHEMA, "valid": False, "reason": reason}
    if not isinstance(checked_at, datetime) or checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")
    if type(max_age_days) is not int or not 1 <= max_age_days <= 365:
        raise ValueError("Invalid max_age_days")
    if not isinstance(digest_bytes, bytes) or not digest_bytes or len(digest_bytes) > MAX_DIGEST_BYTES:
        return denied("invalid_digest_bytes")
    if not isinstance(expected_digest_sha256, str) or not SHA.fullmatch(expected_digest_sha256):
        return denied("invalid_expected_digest")
    if hashlib.sha256(digest_bytes).hexdigest() != expected_digest_sha256:
        return denied("digest_sha256_mismatch")
    if not isinstance(signed_message, bytes) or not signed_message or len(signed_message) > 4096:
        return denied("invalid_signed_message")
    if not isinstance(trusted_rsa_public_key, rsa.RSAPublicKey) or trusted_rsa_public_key.key_size < 2048:
        return denied("untrusted_or_weak_rsa_key")
    if not isinstance(signature_hex, str) or len(signature_hex) != trusted_rsa_public_key.key_size // 4:
        return denied("invalid_signature")
    try:
        trusted_rsa_public_key.verify(bytes.fromhex(signature_hex), signed_message,
                                      padding.PKCS1v15(), hashes.SHA256())
    except (ValueError, InvalidSignature, TypeError):
        return denied("rsa_signature_invalid")
    try:
        document = json.loads(digest_bytes.decode("utf-8"))
    except (UnicodeError, ValueError):
        return denied("invalid_digest_json")
    if not isinstance(document, dict) or not isinstance(document.get("logFiles"), list):
        return denied("missing_log_manifest")
    manifest = document["logFiles"]
    if not isinstance(expected_log_paths, set) or not expected_log_paths or len(expected_log_paths) > 1000:
        return denied("invalid_expected_paths")
    if not isinstance(log_files, dict) or set(log_files) != expected_log_paths:
        return denied("log_file_set_mismatch")
    found = set()
    for record in manifest:
        if not isinstance(record, dict):
            return denied("invalid_log_manifest")
        path = record.get("s3Object")
        expected_hash = record.get("hashValue")
        algorithm = record.get("hashAlgorithm")
        if (not isinstance(path, str) or path not in expected_log_paths or path in found
                or algorithm != "SHA-256" or not isinstance(expected_hash, str)
                or not SHA.fullmatch(expected_hash)):
            return denied("unexpected_or_invalid_log_entry")
        data = log_files[path]
        if not isinstance(data, bytes) or not data or len(data) > MAX_LOG_BYTES:
            return denied("invalid_log_bytes")
        if hashlib.sha256(data).hexdigest() != expected_hash:
            return denied("log_hash_mismatch")
        found.add(path)
    if found != expected_log_paths:
        return denied("missing_log_entry")
    return {"schema": SCHEMA, "valid": True, "log_count": len(found),
            "digest_sha256": expected_digest_sha256,
            "limitations": "RSA verified only over caller-supplied message; AWS signature-message canonicalization, AWS key authenticity and digest-chain continuity not established"}
