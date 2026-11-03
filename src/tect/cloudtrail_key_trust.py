"""Fail-closed trust policy for independently pinned CloudTrail signing keys.

This authenticates a configured RSA key against an independently pinned
fingerprint. It does not establish that the key is an AWS CloudTrail key.
"""
import hashlib
import re
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SCHEMA = "tect.cloudtrail-key-trust.v1"
HEX = re.compile(r"^[0-9a-f]{64}$")
REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")
ACCOUNT = re.compile(r"^[0-9]{12}$")


def _time(value):
    if not isinstance(value, str):
        raise ValueError("Invalid time")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Timezone required")
    return parsed.astimezone(timezone.utc)


def rsa_spki_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """SHA-256 of DER SubjectPublicKeyInfo, not a provider certificate pin."""
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 2048:
        raise ValueError("RSA key must have at least 2048 bits")
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def verify_cloudtrail_key_trust(public_key: rsa.RSAPublicKey, registry: dict, *,
                                key_id: str, region: str, account_id: str,
                                checked_at: datetime, expected_registry_sequence: int) -> dict:
    def denied(reason):
        return {"schema": SCHEMA, "trusted": False, "reason": reason}
    if not isinstance(checked_at, datetime) or checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")
    if type(expected_registry_sequence) is not int or expected_registry_sequence < 1:
        raise ValueError("Positive independently pinned registry sequence required")
    if not isinstance(registry, dict) or set(registry) != {"schema", "sequence", "keys"}:
        return denied("invalid_registry")
    if registry["schema"] != SCHEMA:
        return denied("invalid_schema")
    if type(registry["sequence"]) is not int or registry["sequence"] < expected_registry_sequence:
        return denied("registry_rollback")
    if not isinstance(key_id, str) or not key_id.strip():
        return denied("invalid_key_id")
    if not isinstance(region, str) or not REGION.fullmatch(region):
        return denied("invalid_region")
    if not isinstance(account_id, str) or not ACCOUNT.fullmatch(account_id):
        return denied("invalid_account")
    keys = registry["keys"]
    if not isinstance(keys, dict) or key_id not in keys:
        return denied("unknown_key")
    record = keys[key_id]
    if not isinstance(record, dict) or set(record) != {
        "fingerprint_sha256", "regions", "accounts", "valid_from",
        "valid_until", "revoked", "provenance_reference"}:
        return denied("invalid_key_record")
    fingerprint = record["fingerprint_sha256"]
    if not isinstance(fingerprint, str) or not HEX.fullmatch(fingerprint):
        return denied("invalid_fingerprint")
    if not isinstance(record["regions"], list) or region not in record["regions"]:
        return denied("region_not_approved")
    if not isinstance(record["accounts"], list) or account_id not in record["accounts"]:
        return denied("account_not_approved")
    if record["revoked"] is not False:
        return denied("key_revoked")
    if not isinstance(record["provenance_reference"], str) or not record["provenance_reference"].strip():
        return denied("missing_key_provenance")
    try:
        start = _time(record["valid_from"])
        end = _time(record["valid_until"])
    except (ValueError, TypeError):
        return denied("invalid_key_validity")
    now = checked_at.astimezone(timezone.utc)
    if end <= start or not start <= now <= end:
        return denied("key_outside_validity")
    try:
        actual = rsa_spki_fingerprint(public_key)
    except ValueError:
        return denied("weak_or_invalid_key")
    if actual != fingerprint:
        return denied("key_fingerprint_mismatch")
    return {"schema": SCHEMA, "trusted": True, "key_id": key_id,
            "fingerprint_sha256": actual, "registry_sequence": registry["sequence"],
            "limitations": "Caller-supplied registry and provenance are not authenticated; this does not prove AWS key ownership"}


def verify_pinned_cloudtrail_signature(public_key, registry, *, key_id, region,
                                       account_id, checked_at, expected_registry_sequence,
                                       signed_message: bytes, signature_hex: str) -> dict:
    """Verify RSA signature only after exact key trust checks."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    result = verify_cloudtrail_key_trust(
        public_key, registry, key_id=key_id, region=region,
        account_id=account_id, checked_at=checked_at,
        expected_registry_sequence=expected_registry_sequence)
    if not result["trusted"]:
        return result
    if not isinstance(signed_message, bytes) or not signed_message or len(signed_message) > 4096:
        return {"schema": SCHEMA, "trusted": False, "reason": "invalid_signed_message"}
    if not isinstance(signature_hex, str) or len(signature_hex) != public_key.key_size // 4:
        return {"schema": SCHEMA, "trusted": False, "reason": "invalid_signature"}
    try:
        public_key.verify(bytes.fromhex(signature_hex), signed_message,
                          padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError, TypeError):
        return {"schema": SCHEMA, "trusted": False, "reason": "signature_invalid"}
    return {**result, "signature_valid": True}
