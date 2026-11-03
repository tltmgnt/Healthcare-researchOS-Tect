"""Portable Ed25519 registry-floor anchors for independent custody.

A signed anchor is useful only when a trusted external party retains the
latest version. This module does not itself publish or anchor remotely.
"""
import re
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .durable_registry_floor import RegistryFloorStore
from .storage import canonical

SCHEMA = "tect.registry-floor-anchor.v1"
SIG = re.compile(r"^[0-9a-f]{128}$")


def sign_floor_anchor(store: RegistryFloorStore, *, authority_key_id: str,
                      private_key: Ed25519PrivateKey, created_at: datetime) -> dict:
    """Sign the current persisted floor for export to independent custody."""
    if not isinstance(store, RegistryFloorStore):
        raise ValueError("RegistryFloorStore required")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Ed25519 private key required")
    if not isinstance(authority_key_id, str) or not authority_key_id.strip():
        raise ValueError("Authority key ID required")
    if not isinstance(created_at, datetime) or created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("Timezone-aware created_at required")
    sequence = store.read()
    payload = {"schema": SCHEMA, "minimum_sequence": sequence,
               "authority_key_id": authority_key_id, "created_at": created_at.isoformat()}
    return {**payload, "signature_hex": private_key.sign(canonical(payload).encode("utf-8")).hex()}


def verify_floor_anchor(envelope: dict, trusted_authorities: dict, *,
                        independently_pinned_sequence: int,
                        checked_at: datetime) -> dict:
    """Verify signature and reject anchors below an external monotonic floor."""
    def denied(reason):
        return {"valid": False, "reason": reason}
    if type(independently_pinned_sequence) is not int or independently_pinned_sequence < 1:
        raise ValueError("Positive independently pinned sequence required")
    if not isinstance(checked_at, datetime) or checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")
    fields = {"schema", "minimum_sequence", "authority_key_id", "created_at", "signature_hex"}
    if not isinstance(envelope, dict) or set(envelope) != fields or envelope.get("schema") != SCHEMA:
        return denied("invalid_anchor")
    sequence = envelope["minimum_sequence"]
    if type(sequence) is not int or sequence < independently_pinned_sequence:
        return denied("anchor_rollback")
    authority_id = envelope["authority_key_id"]
    if not isinstance(authority_id, str) or not authority_id.strip():
        return denied("invalid_authority")
    key = trusted_authorities.get(authority_id) if isinstance(trusted_authorities, dict) else None
    if not isinstance(key, Ed25519PublicKey):
        return denied("untrusted_authority")
    signature = envelope["signature_hex"]
    if not isinstance(signature, str) or not SIG.fullmatch(signature):
        return denied("invalid_signature")
    try:
        payload = {name: envelope[name] for name in fields - {"signature_hex"}}
        key.verify(bytes.fromhex(signature), canonical(payload).encode("utf-8"))
        created_at = datetime.fromisoformat(envelope["created_at"])
    except (InvalidSignature, TypeError, ValueError):
        return denied("signature_or_timestamp_invalid")
    if created_at.tzinfo is None or created_at.utcoffset() is None or created_at > checked_at:
        return denied("invalid_anchor_timestamp")
    return {"valid": True, "minimum_sequence": sequence,
            "authority_key_id": authority_id,
            "limitations": "External custody and pinned latest sequence must be independently enforced"}


def verify_local_floor_against_anchor(store: RegistryFloorStore, envelope: dict,
                                      trusted_authorities: dict, *,
                                      independently_pinned_sequence: int,
                                      checked_at: datetime) -> dict:
    """Require signed external anchor and local floor at least as high."""
    if not isinstance(store, RegistryFloorStore):
        raise ValueError("RegistryFloorStore required")
    anchor = verify_floor_anchor(envelope, trusted_authorities,
                                 independently_pinned_sequence=independently_pinned_sequence,
                                 checked_at=checked_at)
    if not anchor["valid"]:
        return {"ready": False, "reason": "anchor_invalid", "anchor": anchor}
    local = store.read()
    if local < anchor["minimum_sequence"]:
        return {"ready": False, "reason": "local_floor_rollback",
                "local_sequence": local, "anchor_sequence": anchor["minimum_sequence"]}
    return {"ready": True, "local_sequence": local,
            "anchor_sequence": anchor["minimum_sequence"],
            "limitations": "An independently retained latest anchor is required to detect coordinated rollback"}
