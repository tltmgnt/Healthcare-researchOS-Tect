"""Offline, fail-closed release evidence integrity and freshness verification.

Verifies provided bytes and attestation metadata. This is not authentication
of evidence origin, approvers, or production deployment authorization.
"""
import hashlib
import re
from datetime import datetime, timedelta, timezone

from .release_gates import REQUIRED_GATES, evaluate_release_gates

SCHEMA = "tect.release-evidence-integrity.v1"
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_AGE_DAYS = 90
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def verify_release_evidence(gates: dict, artifacts: dict[str, bytes], *,
                            submitter_id: str, assessed_at: datetime | None = None,
                            max_age_days: int = DEFAULT_MAX_AGE_DAYS) -> dict:
    """Require complete gate attestations and bound, fresh evidence bytes.

    A trusted authority must separately authenticate the source and reviewer.
    """
    now = assessed_at if assessed_at is not None else datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Timezone-aware assessed_at required")
    if type(max_age_days) is not int or not 1 <= max_age_days <= 365:
        raise ValueError("max_age_days must be an integer between 1 and 365")
    if not isinstance(gates, dict) or not isinstance(artifacts, dict):
        raise ValueError("Gates and artifacts must be dictionaries")
    if not isinstance(submitter_id, str) or not submitter_id.strip():
        raise ValueError("Nonempty submitter ID required")

    base = evaluate_release_gates(gates, assessed_at=now)
    results = {}
    for gate in REQUIRED_GATES:
        record = gates.get(gate)
        data = artifacts.get(gate)
        reason = None
        if not base["gates"][gate]["passed"] or not isinstance(record, dict):
            reason = "gate_not_attested"
        elif not isinstance(data, bytes) or not 0 < len(data) <= MAX_ARTIFACT_BYTES:
            reason = "artifact_missing_or_invalid"
        elif (not isinstance(record.get("evidence_sha256"), str)
              or not _SHA256.fullmatch(record["evidence_sha256"])
              or hashlib.sha256(data).hexdigest() != record["evidence_sha256"]):
            reason = "artifact_digest_mismatch"
        elif (not isinstance(record.get("independent_approver"), str)
              or record["independent_approver"].strip() == submitter_id.strip()):
            reason = "self_approval_forbidden"
        else:
            try:
                approved_at = datetime.fromisoformat(record["approved_at"].replace("Z", "+00:00"))
                if approved_at.tzinfo is None or approved_at.utcoffset() is None:
                    reason = "invalid_approval_timestamp"
                elif approved_at > now:
                    reason = "future_approval"
                elif now - approved_at > timedelta(days=max_age_days):
                    reason = "stale_approval"
            except (ValueError, TypeError, AttributeError):
                reason = "invalid_approval_timestamp"
        results[gate] = {"verified": reason is None, "reason": reason or "integrity_and_freshness_checked"}

    unexpected_artifacts = sorted(k for k in artifacts if k not in REQUIRED_GATES)
    ready = (base["release_gates_attested"] and
             all(item["verified"] for item in results.values()) and
             not unexpected_artifacts)
    return {"schema": SCHEMA, "evidence_integrity_ready": ready,
            "assessed_at": now.isoformat(), "max_age_days": max_age_days,
            "verified_count": sum(item["verified"] for item in results.values()),
            "required_count": len(REQUIRED_GATES),
            "unexpected_artifacts": unexpected_artifacts,
            "gate_results": results,
            "limitations": "Offline digest/freshness checks only; evidence provenance, approver identity, independence, clinical approval and deployment authorization not authenticated"}
