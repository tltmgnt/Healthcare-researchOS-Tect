"""Operator-attested live-provider validation evidence checklist.

Never calls cloud APIs or performs deletion. Attestations require evidence
references; they do not independently prove the stated controls.
"""
from datetime import datetime, timezone

REQUIRED_CONTROLS = (
    "independent_storage_account",
    "object_lock_compliance_retention",
    "denied_deletion_test",
    "independent_signing_key_custody",
    "anchor_retrieval_and_recovery",
    "credential_rotation_and_revocation",
)


def evaluate_provider_validation(attestations: dict, *, checked_at: datetime | None = None) -> dict:
    """Return fail-closed readiness status with missing/failed evidence controls."""
    current = checked_at if checked_at is not None else datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")
    if not isinstance(attestations, dict):
        raise ValueError("Attestations must be a dictionary")
    results = {}
    for name in REQUIRED_CONTROLS:
        record = attestations.get(name)
        if not isinstance(record, dict):
            results[name] = {"accepted": False, "reason": "missing_record"}
            continue
        passed = record.get("passed") is True
        reference = record.get("evidence_reference")
        reviewer = record.get("reviewer")
        reviewed_at = record.get("reviewed_at")
        accepted = (passed and isinstance(reference, str) and bool(reference.strip())
                    and isinstance(reviewer, str) and bool(reviewer.strip())
                    and isinstance(reviewed_at, str) and bool(reviewed_at.strip()))
        results[name] = {"accepted": accepted,
                         "reason": "attested_with_reference" if accepted else "incomplete_or_failed"}
    return {"ready": all(r["accepted"] for r in results.values()),
            "checked_at": current.isoformat(), "controls": results,
            "accepted_count": sum(r["accepted"] for r in results.values()),
            "required_count": len(REQUIRED_CONTROLS),
            "limitations": "Operator attestations only; evidence authenticity and live controls not independently verified"}
