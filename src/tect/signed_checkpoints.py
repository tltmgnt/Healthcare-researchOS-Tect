"""HMAC-SHA256 signed checkpoint envelope, for separately managed shared secrets.

This is a symmetric MAC, not a public-key digital signature. The verifier
possesses signing authority; use asymmetric signatures for independent auditors.
"""
import hashlib
import hmac
import json
from .checkpoints import export_checkpoint, verify_checkpoint

SCHEMA = "tect.signed-checkpoint.hmac-sha256.v1"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_checkpoint(secret: bytes, key_id: str) -> dict:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("A secret of at least 32 bytes is required")
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("A non-empty key identifier is required")
    envelope = {"schema": SCHEMA, "key_id": key_id, "checkpoint": export_checkpoint()}
    envelope["mac"] = hmac.new(secret, canonical(envelope).encode(), hashlib.sha256).hexdigest()
    return envelope


def verify_signed_checkpoint(envelope: dict, trusted_keys: dict[str, bytes]) -> dict:
    if not isinstance(envelope, dict) or set(envelope) != {"schema", "key_id", "checkpoint", "mac"}:
        return {"valid": False, "reason": "invalid_envelope"}
    if envelope["schema"] != SCHEMA or not isinstance(envelope["key_id"], str):
        return {"valid": False, "reason": "invalid_envelope"}
    secret = trusted_keys.get(envelope["key_id"])
    if not isinstance(secret, bytes) or len(secret) < 32:
        return {"valid": False, "reason": "unknown_key"}
    mac = envelope["mac"]
    if not isinstance(mac, str) or len(mac) != 64:
        return {"valid": False, "reason": "invalid_mac"}
    payload = {k: envelope[k] for k in ("schema", "key_id", "checkpoint")}
    expected = hmac.new(secret, canonical(payload).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        return {"valid": False, "reason": "signature_mismatch"}
    return verify_checkpoint(envelope["checkpoint"])
