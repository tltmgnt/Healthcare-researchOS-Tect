"""Ed25519 signed operator validation evidence bundles.

Signatures attest to bundle bytes, not truth of external control claims.
"""
import re
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .provider_validation import REQUIRED_CONTROLS, evaluate_provider_validation
from .storage import canonical

SCHEMA = "tect.provider-validation-evidence.ed25519.v1"
_HEX_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")


def sign_validation_bundle(attestations: dict, private_key: Ed25519PrivateKey,
                           key_id: str, *, signed_at: datetime | None = None) -> dict:
    """Sign an explicitly reviewed, complete checklist; reject incomplete controls."""
    if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("Ed25519 private key and nonempty key_id required")
    current = signed_at if signed_at is not None else datetime.now(timezone.utc)
    result = evaluate_provider_validation(attestations, checked_at=current)
    if not result["ready"]:
        raise ValueError("Validation checklist incomplete or failed")
    if set(attestations) != set(REQUIRED_CONTROLS):
        raise ValueError("Unexpected validation controls")
    payload = {"schema": SCHEMA, "key_id": key_id, "signed_at": current.isoformat(),
               "attestations": attestations}
    return {**payload, "signature_hex": private_key.sign(canonical(payload).encode("utf-8")).hex()}


def verify_validation_bundle(bundle: dict, trusted_public_keys: dict[str, Ed25519PublicKey]) -> dict:
    """Validate exact schema, trusted reviewer signature, and checklist completeness."""
    required = {"schema", "key_id", "signed_at", "attestations", "signature_hex"}
    if not isinstance(bundle, dict) or set(bundle) != required or bundle.get("schema") != SCHEMA:
        return {"valid": False, "reason": "invalid_bundle"}
    key_id = bundle["key_id"]
    if not isinstance(key_id, str) or not key_id.strip() or not isinstance(bundle["signed_at"], str):
        return {"valid": False, "reason": "invalid_bundle"}
    try:
        timestamp = datetime.fromisoformat(bundle["signed_at"])
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            return {"valid": False, "reason": "invalid_bundle"}
    except ValueError:
        return {"valid": False, "reason": "invalid_bundle"}
    if not isinstance(bundle["attestations"], dict) or set(bundle["attestations"]) != set(REQUIRED_CONTROLS):
        return {"valid": False, "reason": "invalid_bundle"}
    signature = bundle["signature_hex"]
    if not isinstance(signature, str) or not _HEX_SIGNATURE.fullmatch(signature):
        return {"valid": False, "reason": "invalid_signature"}
    if not isinstance(trusted_public_keys, dict):
        return {"valid": False, "reason": "untrusted_key"}
    key = trusted_public_keys.get(key_id)
    if not isinstance(key, Ed25519PublicKey):
        return {"valid": False, "reason": "untrusted_key"}
    payload = {name: bundle[name] for name in required - {"signature_hex"}}
    try:
        key.verify(bytes.fromhex(signature), canonical(payload).encode("utf-8"))
    except (InvalidSignature, ValueError, TypeError):
        return {"valid": False, "reason": "signature_mismatch"}
    result = evaluate_provider_validation(bundle["attestations"], checked_at=timestamp)
    if not result["ready"]:
        return {"valid": False, "reason": "incomplete_attestations"}
    return {"valid": True, "key_id": key_id, "signed_at": bundle["signed_at"],
            "controls_checked": result["required_count"],
            "limitations": "Signature authenticates attestations, not external evidence or provider controls"}
