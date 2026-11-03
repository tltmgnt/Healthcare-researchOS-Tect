"""Signed, versioned reviewer trust registry with external anti-rollback floor.

The minimum accepted sequence MUST come from independently durable storage.
"""
import re
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .release_gates import REQUIRED_GATES
from .reviewer_trust_registry import verify_with_reviewer_registry
from .storage import canonical

SCHEMA = "tect.signed-reviewer-registry.v1"
HEX = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE = re.compile(r"^[0-9a-f]{128}$")
ENTRY_FIELDS = {"public_key_hex", "reviewer_id", "allowed_submitters", "allowed_gates",
                "valid_from", "valid_until", "revoked"}


def sign_trust_registry(entries: dict, *, sequence: int, authority_key_id: str,
                        authority_private_key: Ed25519PrivateKey) -> dict:
    """Sign a portable JSON-serializable registry snapshot."""
    if type(sequence) is not int or sequence < 1:
        raise ValueError("Positive integer sequence required")
    if not isinstance(authority_key_id, str) or not authority_key_id.strip():
        raise ValueError("Authority key ID required")
    if not isinstance(authority_private_key, Ed25519PrivateKey):
        raise ValueError("Ed25519 authority key required")
    if not isinstance(entries, dict):
        raise ValueError("Registry entries must be a dictionary")
    payload = {"schema": SCHEMA, "sequence": sequence,
               "authority_key_id": authority_key_id, "entries": entries}
    try:
        data = canonical(payload).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Registry entries must be JSON serializable") from exc
    return {**payload, "signature_hex": authority_private_key.sign(data).hex()}


def verify_signed_trust_registry(envelope: dict, trusted_authorities: dict, *,
                                 minimum_sequence: int) -> dict:
    """Verify trusted authority signature and independently supplied floor."""
    def denied(reason):
        return {"valid": False, "reason": reason}
    if type(minimum_sequence) is not int or minimum_sequence < 1:
        raise ValueError("Independently pinned minimum sequence required")
    fields = {"schema", "sequence", "authority_key_id", "entries", "signature_hex"}
    if not isinstance(envelope, dict) or set(envelope) != fields or envelope.get("schema") != SCHEMA:
        return denied("invalid_envelope")
    sequence = envelope["sequence"]
    if type(sequence) is not int or sequence < minimum_sequence:
        return denied("registry_rollback")
    key_id = envelope["authority_key_id"]
    if not isinstance(key_id, str) or not key_id.strip():
        return denied("invalid_authority")
    key = trusted_authorities.get(key_id) if isinstance(trusted_authorities, dict) else None
    if not isinstance(key, Ed25519PublicKey):
        return denied("untrusted_authority")
    signature = envelope["signature_hex"]
    if not isinstance(signature, str) or not SIGNATURE.fullmatch(signature):
        return denied("invalid_signature")
    try:
        payload = {name: envelope[name] for name in fields - {"signature_hex"}}
        key.verify(bytes.fromhex(signature), canonical(payload).encode("utf-8"))
    except (InvalidSignature, TypeError, ValueError):
        return denied("signature_mismatch")
    entries = envelope["entries"]
    if not isinstance(entries, dict):
        return denied("invalid_registry_entries")
    registry = {}
    for reviewer_key_id, entry in entries.items():
        if not isinstance(reviewer_key_id, str) or not reviewer_key_id.strip():
            return denied("invalid_registry_entries")
        if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
            return denied("invalid_registry_entries")
        hex_key = entry["public_key_hex"]
        if not isinstance(hex_key, str) or not HEX.fullmatch(hex_key):
            return denied("invalid_registry_entries")
        try:
            reviewer_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key))
            start = datetime.fromisoformat(entry["valid_from"])
            end = datetime.fromisoformat(entry["valid_until"])
        except (ValueError, TypeError, KeyError):
            return denied("invalid_registry_entries")
        if (start.tzinfo is None or end.tzinfo is None
                or start.utcoffset() is None or end.utcoffset() is None
                or start > end
                or not isinstance(entry["reviewer_id"], str) or not entry["reviewer_id"].strip()
                or not isinstance(entry["allowed_submitters"], list)
                or not entry["allowed_submitters"]
                or any(not isinstance(x, str) or not x.strip() for x in entry["allowed_submitters"])
                or not isinstance(entry["allowed_gates"], list)
                or set(entry["allowed_gates"]) != set(REQUIRED_GATES)
                or len(entry["allowed_gates"]) != len(REQUIRED_GATES)
                or type(entry["revoked"]) is not bool):
            return denied("invalid_registry_entries")
        registry[reviewer_key_id] = {
            "public_key": reviewer_key, "reviewer_id": entry["reviewer_id"],
            "allowed_submitters": set(entry["allowed_submitters"]),
            "allowed_gates": set(entry["allowed_gates"]),
            "valid_from": start, "valid_until": end, "revoked": entry["revoked"]}
    return {"valid": True, "sequence": sequence, "registry": registry,
            "limitations": "Anti-rollback depends on independently stored minimum sequence and authenticated authority keys"}


def verify_release_with_signed_registry(release_envelope: dict, artifacts: dict,
                                        registry_envelope: dict, trusted_authorities: dict, *,
                                        minimum_sequence: int, expected_submitter_id: str,
                                        assessed_at: datetime) -> dict:
    """Gate Phase 33 reviewer verification on signed registry authenticity."""
    verified = verify_signed_trust_registry(
        registry_envelope, trusted_authorities, minimum_sequence=minimum_sequence)
    if not verified["valid"]:
        return {"authorized": False, "release_evidence_ready": False,
                "reason": "registry_verification_failed", "registry_reason": verified["reason"]}
    result = verify_with_reviewer_registry(
        release_envelope, artifacts, verified["registry"],
        expected_submitter_id=expected_submitter_id, assessed_at=assessed_at)
    return {**result, "registry_sequence": verified["sequence"]}


def encode_reviewer_public_key(key: Ed25519PublicKey) -> str:
    """Serialize a reviewer public key for a signed registry entry."""
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Ed25519 public key required")
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
