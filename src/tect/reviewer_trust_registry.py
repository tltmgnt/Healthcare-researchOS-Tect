"""Offline reviewer-key authorization registry for signed release evidence.

Registry policy must be provisioned and authenticated out of band.
"""
import re
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .release_gates import REQUIRED_GATES
from .signed_release_evidence import verify_signed_release_evidence

SCHEMA = "tect.reviewer-trust-registry.v1"
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def verify_with_reviewer_registry(envelope: dict, artifacts: dict[str, bytes],
                                  registry: dict, *, expected_submitter_id: str,
                                  assessed_at: datetime) -> dict:
    """Require scoped active key before verifying signature and artifact bytes."""
    def denied(reason: str) -> dict:
        return {"schema": SCHEMA, "authorized": False,
                "release_evidence_ready": False, "reason": reason}
    if not isinstance(assessed_at, datetime) or assessed_at.tzinfo is None or assessed_at.utcoffset() is None:
        raise ValueError("Timezone-aware verification date required")
    if not isinstance(envelope, dict) or not isinstance(registry, dict):
        return denied("invalid_input")
    key_id = envelope.get("reviewer_key_id")
    if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
        return denied("invalid_reviewer_key_id")
    entry = registry.get(key_id)
    if not isinstance(entry, dict) or set(entry) != {
        "public_key", "reviewer_id", "allowed_submitters", "allowed_gates",
        "valid_from", "valid_until", "revoked"
    }:
        return denied("reviewer_not_registered")
    if not isinstance(entry["public_key"], Ed25519PublicKey):
        return denied("invalid_reviewer_public_key")
    if entry["revoked"] is not False:
        return denied("reviewer_key_revoked")
    if not isinstance(entry["reviewer_id"], str) or not entry["reviewer_id"].strip():
        return denied("invalid_reviewer_identity")
    if entry["reviewer_id"] == expected_submitter_id:
        return denied("reviewer_submitter_conflict")
    if (not isinstance(entry["allowed_submitters"], (set, frozenset))
            or expected_submitter_id not in entry["allowed_submitters"]):
        return denied("submitter_not_authorized")
    if (not isinstance(entry["allowed_gates"], (set, frozenset))
            or set(REQUIRED_GATES) != entry["allowed_gates"]):
        return denied("gate_scope_not_authorized")
    start, end = entry["valid_from"], entry["valid_until"]
    if (not isinstance(start, datetime) or not isinstance(end, datetime)
            or start.tzinfo is None or end.tzinfo is None
            or start.utcoffset() is None or end.utcoffset() is None
            or not start <= assessed_at <= end):
        return denied("reviewer_key_outside_validity")
    result = verify_signed_release_evidence(
        envelope, artifacts, {key_id: entry["public_key"]},
        expected_submitter_id=expected_submitter_id, assessed_at=assessed_at)
    return {"schema": SCHEMA, "authorized": bool(result.get("valid")),
            "release_evidence_ready": bool(result.get("release_evidence_ready")),
            "reviewer_id": entry["reviewer_id"], "signature_result": result,
            "limitations": "Registry is caller-supplied; external authentication, organizational independence and custody must be established separately"}
