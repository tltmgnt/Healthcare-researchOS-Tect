"""Ed25519 checkpoint signatures with public-key-only verification.

Public keys must be distributed through a separately trusted registry.
"""
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .checkpoints import export_checkpoint, verify_checkpoint

SCHEMA = "tect.signed-checkpoint.ed25519.v1"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_checkpoint(private_key: Ed25519PrivateKey, key_id: str) -> dict:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Ed25519 private key required")
    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("Non-empty key identifier required")
    envelope = {"schema": SCHEMA, "key_id": key_id, "checkpoint": export_checkpoint()}
    envelope["signature_hex"] = private_key.sign(_canonical(envelope)).hex()
    return envelope


def verify_signed_checkpoint(envelope: dict, trusted_public_keys: dict[str, Ed25519PublicKey]) -> dict:
    if not isinstance(envelope, dict) or set(envelope) != {"schema", "key_id", "checkpoint", "signature_hex"}:
        return {"valid": False, "reason": "invalid_envelope"}
    if envelope["schema"] != SCHEMA or not isinstance(envelope["key_id"], str):
        return {"valid": False, "reason": "invalid_envelope"}
    public_key = trusted_public_keys.get(envelope["key_id"])
    if not isinstance(public_key, Ed25519PublicKey):
        return {"valid": False, "reason": "untrusted_key"}
    signature = envelope["signature_hex"]
    if not isinstance(signature, str) or len(signature) != 128:
        return {"valid": False, "reason": "invalid_signature"}
    try:
        signature_bytes = bytes.fromhex(signature)
    except ValueError:
        return {"valid": False, "reason": "invalid_signature"}
    signed_content = {k: envelope[k] for k in ("schema", "key_id", "checkpoint")}
    try:
        public_key.verify(signature_bytes, _canonical(signed_content))
    except (InvalidSignature, TypeError, ValueError):
        return {"valid": False, "reason": "signature_mismatch"}
    return verify_checkpoint(envelope["checkpoint"])
