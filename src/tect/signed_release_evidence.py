"""Ed25519 reviewer signatures over complete release evidence gate submissions.

Signatures bind metadata and digests; actual evidence bytes are verified
separately before a signed release-evidence verdict is returned.
"""
import re
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .release_evidence_integrity import verify_release_evidence
from .storage import canonical

SCHEMA = "tect.signed-release-evidence.v1"
_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")


def sign_release_evidence(gates: dict, *, submitter_id: str,
                          reviewer_key_id: str, private_key: Ed25519PrivateKey,
                          assessed_at: datetime, max_age_days: int = 90) -> dict:
    """Create reviewer signature over complete gate attestations and digests."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Ed25519 signing key required")
    if not isinstance(reviewer_key_id, str) or not reviewer_key_id.strip():
        raise ValueError("Nonempty reviewer key ID required")
    if not isinstance(submitter_id, str) or not submitter_id.strip():
        raise ValueError("Nonempty submitter ID required")
    if not isinstance(assessed_at, datetime) or assessed_at.tzinfo is None or assessed_at.utcoffset() is None:
        raise ValueError("Timezone-aware assessment date required")
    if type(max_age_days) is not int or not 1 <= max_age_days <= 365:
        raise ValueError("Invalid maximum evidence age")
    if not isinstance(gates, dict):
        raise ValueError("Gate records must be a dictionary")
    payload = {"schema": SCHEMA, "gates": gates, "submitter_id": submitter_id,
               "reviewer_key_id": reviewer_key_id,
               "assessed_at": assessed_at.isoformat(), "max_age_days": max_age_days}
    try:
        message = canonical(payload).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Gate records must be JSON serializable") from exc
    return {**payload, "signature_hex": private_key.sign(message).hex()}


def verify_signed_release_evidence(envelope: dict, artifacts: dict[str, bytes],
                                   trusted_reviewer_keys: dict[str, Ed25519PublicKey], *,
                                   expected_submitter_id: str,
                                   assessed_at: datetime) -> dict:
    """Fail closed on signature, scope, freshness, or artifact tampering."""
    def denied(reason: str, **details) -> dict:
        return {"valid": False, "release_evidence_ready": False,
                "reason": reason, **details}
    fields = {"schema", "gates", "submitter_id", "reviewer_key_id",
              "assessed_at", "max_age_days", "signature_hex"}
    if not isinstance(envelope, dict) or set(envelope) != fields or envelope.get("schema") != SCHEMA:
        return denied("invalid_envelope")
    if not isinstance(expected_submitter_id, str) or envelope["submitter_id"] != expected_submitter_id:
        return denied("submitter_mismatch")
    reviewer = envelope["reviewer_key_id"]
    if not isinstance(reviewer, str) or not reviewer.strip():
        return denied("invalid_reviewer")
    key = trusted_reviewer_keys.get(reviewer) if isinstance(trusted_reviewer_keys, dict) else None
    if not isinstance(key, Ed25519PublicKey):
        return denied("untrusted_reviewer")
    signature = envelope["signature_hex"]
    if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
        return denied("invalid_signature")
    payload = {name: envelope[name] for name in fields - {"signature_hex"}}
    try:
        key.verify(bytes.fromhex(signature), canonical(payload).encode("utf-8"))
    except (InvalidSignature, TypeError, ValueError):
        return denied("signature_mismatch")
    if not isinstance(assessed_at, datetime) or assessed_at.tzinfo is None or assessed_at.utcoffset() is None:
        raise ValueError("Timezone-aware verification date required")
    try:
        signed_at = datetime.fromisoformat(envelope["assessed_at"])
        if signed_at.tzinfo is None or signed_at.utcoffset() is None:
            return denied("invalid_assessment_timestamp")
        if signed_at > assessed_at:
            return denied("future_assessment")
        # Never extend the signed assessment date to make stale approvals look fresh.
        if (assessed_at - signed_at).total_seconds() > 86400:
            return denied("stale_assessment")
        integrity = verify_release_evidence(
            envelope["gates"], artifacts, submitter_id=expected_submitter_id,
            assessed_at=assessed_at, max_age_days=envelope["max_age_days"])
    except (TypeError, ValueError, OverflowError):
        return denied("invalid_signed_payload")
    return {"valid": True, "release_evidence_ready": integrity["evidence_integrity_ready"],
            "reviewer_key_id": reviewer, "integrity": integrity,
            "limitations": "Signature verifies trusted-key possession and artifact digests, not real-world reviewer identity, evidence provenance or production authorization"}
