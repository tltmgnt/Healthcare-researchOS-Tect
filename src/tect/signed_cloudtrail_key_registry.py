"""Independent Ed25519 signature and sequence pin for CloudTrail key registry.

Authenticates an independently configured registry authority key, not AWS
ownership of any CloudTrail signing key.
"""
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .cloudtrail_key_trust import SCHEMA as KEY_SCHEMA, verify_cloudtrail_key_trust

SCHEMA = "tect.signed-cloudtrail-key-registry.v1"
MAX_REGISTRY_BYTES = 256 * 1024


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _valid_registry(registry):
    return (isinstance(registry, dict) and set(registry) == {"schema", "sequence", "keys"}
            and registry["schema"] == KEY_SCHEMA
            and type(registry["sequence"]) is int and registry["sequence"] > 0
            and isinstance(registry["keys"], dict) and bool(registry["keys"]))


def sign_cloudtrail_key_registry(registry: dict, *, authority_key_id: str,
                                 authority_private_key: Ed25519PrivateKey) -> dict:
    if not _valid_registry(registry):
        raise ValueError("Invalid key registry")
    if not isinstance(authority_key_id, str) or not authority_key_id.strip():
        raise ValueError("Authority key ID required")
    if not isinstance(authority_private_key, Ed25519PrivateKey):
        raise ValueError("Ed25519 authority key required")
    payload = {"schema": SCHEMA, "authority_key_id": authority_key_id, "registry": registry}
    encoded = _canonical(payload)
    if len(encoded) > MAX_REGISTRY_BYTES:
        raise ValueError("Registry too large")
    return {"payload": payload, "signature_hex": authority_private_key.sign(encoded).hex()}


def verify_signed_cloudtrail_key_registry(envelope: dict, trusted_authorities: dict, *,
                                           minimum_sequence: int) -> dict:
    def denied(reason):
        return {"valid": False, "reason": reason}
    if type(minimum_sequence) is not int or minimum_sequence < 1:
        raise ValueError("Positive independently pinned sequence required")
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature_hex"}:
        return denied("invalid_envelope")
    payload = envelope["payload"]
    if not isinstance(payload, dict) or set(payload) != {"schema", "authority_key_id", "registry"}:
        return denied("invalid_payload")
    if payload["schema"] != SCHEMA or not _valid_registry(payload["registry"]):
        return denied("invalid_registry")
    if payload["registry"]["sequence"] < minimum_sequence:
        return denied("registry_rollback")
    key_id = payload["authority_key_id"]
    if not isinstance(key_id, str) or not key_id.strip():
        return denied("invalid_authority")
    authority = trusted_authorities.get(key_id) if isinstance(trusted_authorities, dict) else None
    if not isinstance(authority, Ed25519PublicKey):
        return denied("untrusted_authority")
    try:
        encoded = _canonical(payload)
    except (TypeError, ValueError):
        return denied("invalid_payload_encoding")
    if len(encoded) > MAX_REGISTRY_BYTES:
        return denied("registry_too_large")
    signature = envelope["signature_hex"]
    if not isinstance(signature, str) or len(signature) != 128:
        return denied("invalid_signature")
    try:
        authority.verify(bytes.fromhex(signature), encoded)
    except (ValueError, TypeError, InvalidSignature):
        return denied("signature_invalid")
    return {"valid": True, "registry": payload["registry"],
            "sequence": payload["registry"]["sequence"], "authority_key_id": key_id,
            "limitations": "Signed registry authority is caller-configured; AWS key ownership and durable anti-rollback pin remain unverified"}


def verify_cloudtrail_key_with_signed_registry(public_key, envelope, trusted_authorities, *,
                                                minimum_sequence: int, key_id: str,
                                                region: str, account_id: str,
                                                checked_at: datetime) -> dict:
    signed = verify_signed_cloudtrail_key_registry(
        envelope, trusted_authorities, minimum_sequence=minimum_sequence)
    if not signed["valid"]:
        return {"trusted": False, "reason": "signed_registry_invalid", "detail": signed["reason"]}
    return verify_cloudtrail_key_trust(
        public_key, signed["registry"], key_id=key_id, region=region,
        account_id=account_id, checked_at=checked_at,
        expected_registry_sequence=minimum_sequence)
