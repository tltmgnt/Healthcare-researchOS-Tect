"""Verify a signed checkpoint against the historical prefix of a live audit log.

The full current chain is validated before accepting a historical checkpoint.
"""
import hashlib
import hmac
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .checkpoints import SCHEMA as CHECKPOINT_SCHEMA
from .ed25519_checkpoints import SCHEMA as SIGNED_SCHEMA
from .storage import canonical, connect, sha256


def verify_audit_prefix(events_checked: int, expected_head_hash: str) -> dict:
    if type(events_checked) is not int or events_checked < 0:
        return {"valid": False, "reason": "invalid_sequence"}
    if not isinstance(expected_head_hash, str) or len(expected_head_hash) != 64:
        return {"valid": False, "reason": "invalid_head"}
    with connect() as db:
        rows = db.execute(
            "SELECT seq, event_type, claim_id, version, timestamp, payload_sha256, previous_hash, event_hash "
            "FROM events ORDER BY seq"
        ).fetchall()
        previous = "0" * 64
        historical_head = previous if events_checked == 0 else None
        for index, (seq, kind, claim_id, version, timestamp, payload_hash, prev_hash, event_hash) in enumerate(rows, 1):
            event = dict(event_type=kind, claim_id=claim_id, version=version, timestamp=timestamp,
                         payload_sha256=payload_hash, previous_hash=prev_hash)
            payload_row = db.execute(
                "SELECT payload FROM claims WHERE id=? AND version=?", (claim_id, version)
            ).fetchone()
            if (seq != index or prev_hash != previous or sha256(canonical(event)) != event_hash
                    or payload_row is None or sha256(payload_row[0]) != payload_hash):
                return {"valid": False, "reason": "audit_chain_invalid", "failed_sequence": index}
            previous = event_hash
            if index == events_checked:
                historical_head = previous
        if historical_head is None:
            return {"valid": False, "reason": "checkpoint_ahead_of_log"}
        if not hmac.compare_digest(historical_head, expected_head_hash):
            return {"valid": False, "reason": "historical_head_mismatch"}
        return {"valid": True, "events_checked": events_checked, "current_events": len(rows)}


def verify_historical_signed_checkpoint(envelope: dict, trusted_public_keys: dict[str, Ed25519PublicKey]) -> dict:
    if not isinstance(envelope, dict) or set(envelope) != {"schema", "key_id", "checkpoint", "signature_hex"}:
        return {"valid": False, "reason": "invalid_envelope"}
    if envelope["schema"] != SIGNED_SCHEMA or not isinstance(envelope["key_id"], str):
        return {"valid": False, "reason": "invalid_envelope"}
    key = trusted_public_keys.get(envelope["key_id"])
    if not isinstance(key, Ed25519PublicKey):
        return {"valid": False, "reason": "untrusted_key"}
    signature = envelope["signature_hex"]
    if not isinstance(signature, str) or len(signature) != 128:
        return {"valid": False, "reason": "invalid_signature"}
    try:
        signature_bytes = bytes.fromhex(signature)
        signed = {k: envelope[k] for k in ("schema", "key_id", "checkpoint")}
        key.verify(signature_bytes, canonical(signed).encode())
    except (InvalidSignature, TypeError, ValueError, KeyError):
        return {"valid": False, "reason": "signature_mismatch"}
    checkpoint = envelope["checkpoint"]
    required = {"schema", "events_checked", "head_hash", "exported_at", "manifest_sha256"}
    if not isinstance(checkpoint, dict) or set(checkpoint) != required or checkpoint["schema"] != CHECKPOINT_SCHEMA:
        return {"valid": False, "reason": "invalid_manifest"}
    if not isinstance(checkpoint["exported_at"], str) or not isinstance(checkpoint["manifest_sha256"], str):
        return {"valid": False, "reason": "invalid_manifest"}
    digest = hashlib.sha256(canonical({k: checkpoint[k] for k in required - {"manifest_sha256"}}).encode()).hexdigest()
    if not hmac.compare_digest(digest, checkpoint["manifest_sha256"]):
        return {"valid": False, "reason": "manifest_modified"}
    return verify_audit_prefix(checkpoint["events_checked"], checkpoint["head_hash"])
