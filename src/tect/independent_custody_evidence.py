"""Signed independent-custody and deletion-denial assessment evidence.

A signature authenticates an authorized assessor key, not the underlying
provider actions. No destructive provider calls are made.
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "tect.independent-custody-assessment.v1"
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
CONTROLS = (
    "independent_storage_account",
    "independent_key_custody",
    "version_pinned_anchor_retrieval",
    "compliance_retention_verified",
    "protected_version_deletion_denied",
    "credential_revocation_exercised",
)


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _time(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Timezone-aware timestamp required")
    return parsed.astimezone(timezone.utc)


def _validate(payload, artifacts, *, checked_at, max_age_days):
    if not isinstance(payload, dict) or set(payload) != {
        "schema", "assessor_key_id", "assessor_id", "operator_id",
        "approved_account_id", "bucket", "key", "version_id",
        "approval_reference", "assessed_at", "controls"}:
        return "invalid_payload"
    if payload["schema"] != SCHEMA:
        return "invalid_schema"
    for field in ("assessor_key_id", "assessor_id", "operator_id", "bucket",
                  "key", "version_id", "approval_reference"):
        if not isinstance(payload[field], str) or not payload[field].strip():
            return "invalid_identity_or_target"
    if payload["assessor_id"] == payload["operator_id"]:
        return "assessor_not_independent"
    account = payload["approved_account_id"]
    if not isinstance(account, str) or len(account) != 12 or not account.isdigit():
        return "invalid_account"
    try:
        assessed = _time(payload["assessed_at"])
    except (TypeError, ValueError):
        return "invalid_assessment_time"
    if assessed > checked_at or checked_at - assessed > timedelta(days=max_age_days):
        return "stale_or_future_assessment"
    controls = payload["controls"]
    if not isinstance(controls, dict) or set(controls) != set(CONTROLS):
        return "incomplete_controls"
    if not isinstance(artifacts, dict) or set(artifacts) != set(CONTROLS):
        return "incomplete_artifacts"
    for control in CONTROLS:
        record = controls[control]
        if not isinstance(record, dict) or set(record) != {"passed", "reference", "sha256"}:
            return "invalid_control"
        if record["passed"] is not True or not isinstance(record["reference"], str) or not record["reference"].strip():
            return "control_not_passed"
        artifact = artifacts[control]
        if not isinstance(artifact, bytes) or not artifact or len(artifact) > MAX_ARTIFACT_BYTES:
            return "invalid_artifact"
        if record["sha256"] != hashlib.sha256(artifact).hexdigest():
            return "artifact_digest_mismatch"
    return None


def sign_custody_assessment(payload: dict, artifacts: dict, *,
                            assessor_private_key: Ed25519PrivateKey,
                            checked_at: datetime, max_age_days: int = 90) -> dict:
    """Sign only a complete, recent, independently attributed assessment."""
    if not isinstance(assessor_private_key, Ed25519PrivateKey):
        raise ValueError("Ed25519 assessor key required")
    if type(max_age_days) is not int or not 1 <= max_age_days <= 365:
        raise ValueError("Invalid age policy")
    if not isinstance(checked_at, datetime) or checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")
    reason = _validate(payload, artifacts, checked_at=checked_at.astimezone(timezone.utc),
                       max_age_days=max_age_days)
    if reason:
        raise ValueError(reason)
    return {"payload": payload, "signature_hex": assessor_private_key.sign(_canonical(payload)).hex()}


def verify_custody_assessment(envelope: dict, artifacts: dict, trusted_assessors: dict, *,
                              expected_account_id: str, expected_bucket: str,
                              expected_key: str, expected_version_id: str,
                              expected_operator_id: str, checked_at: datetime,
                              max_age_days: int = 90) -> dict:
    def denied(reason):
        return {"valid": False, "reason": reason}
    if type(max_age_days) is not int or not 1 <= max_age_days <= 365:
        raise ValueError("Invalid age policy")
    if not isinstance(checked_at, datetime) or checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature_hex"}:
        return denied("invalid_envelope")
    payload = envelope["payload"]
    reason = _validate(payload, artifacts, checked_at=checked_at.astimezone(timezone.utc),
                       max_age_days=max_age_days)
    if reason:
        return denied(reason)
    if (payload["approved_account_id"] != expected_account_id
            or payload["bucket"] != expected_bucket or payload["key"] != expected_key
            or payload["version_id"] != expected_version_id
            or payload["operator_id"] != expected_operator_id):
        return denied("target_or_operator_mismatch")
    assessor = trusted_assessors.get(payload["assessor_key_id"]) if isinstance(trusted_assessors, dict) else None
    if not isinstance(assessor, Ed25519PublicKey):
        return denied("untrusted_assessor")
    signature = envelope["signature_hex"]
    if not isinstance(signature, str) or len(signature) != 128:
        return denied("invalid_signature")
    try:
        assessor.verify(bytes.fromhex(signature), _canonical(payload))
    except (ValueError, InvalidSignature, TypeError):
        return denied("signature_invalid")
    return {"valid": True, "assessor_id": payload["assessor_id"],
            "approved_account_id": expected_account_id, "version_id": expected_version_id,
            "limitations": "Signed operator-supplied assessment; no live provider or real-world assessor identity proof"}
