"""Explicitly gated, read-only integration assurance runner.

No client construction, mutation, deletion, or credential handling occurs here.
Callers supply a separately configured read-only client and pinned versions.
"""
from datetime import datetime, timezone
from typing import Any

from .independent_evidence_retrieval import verify_retrieved_evidence
from .recovery_assurance import audit_composite_anchor_recovery

SCHEMA = "tect.provider-integration-readonly.v1"


def run_readonly_provider_validation(client: Any, *, enabled: bool,
                                     environment: str, approval_reference: str,
                                     anchor_bucket: str, anchor_key: str,
                                     anchor_version_id: str, anchor_sha256: str,
                                     anchor_trusted_keys: dict,
                                     evidence_manifest: dict, evidence_locations: dict,
                                     reviewer_trusted_keys: dict,
                                     checked_at: datetime | None = None) -> dict:
    """Run only after explicit opt-in and non-production approval.

    This function does not test deletion denial. Results are provider reports,
    not proof of independent custody or enforcement.
    """
    if enabled is not True:
        return {"ready": False, "reason": "explicit_opt_in_required", "schema": SCHEMA}
    if environment != "non-production":
        return {"ready": False, "reason": "non_production_only", "schema": SCHEMA}
    if not isinstance(approval_reference, str) or not approval_reference.strip():
        return {"ready": False, "reason": "approval_reference_required", "schema": SCHEMA}
    current = checked_at if checked_at is not None else datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")
    if not all(isinstance(v, str) and v.strip() for v in
               (anchor_bucket, anchor_key, anchor_version_id, anchor_sha256)):
        return {"ready": False, "reason": "pinned_anchor_required", "schema": SCHEMA}
    if not isinstance(evidence_locations, dict) or not evidence_locations:
        return {"ready": False, "reason": "pinned_evidence_required", "schema": SCHEMA}
    try:
        anchor = audit_composite_anchor_recovery(
            client, anchor_bucket, anchor_key, anchor_version_id,
            anchor_trusted_keys, expected_sha256=anchor_sha256, now=current
        )
    except Exception as exc:
        anchor = {"ready": False, "reason": "anchor_audit_failed",
                  "error_type": type(exc).__name__}
    try:
        evidence = verify_retrieved_evidence(
            client, evidence_manifest, evidence_locations, reviewer_trusted_keys
        )
    except Exception as exc:
        evidence = {"valid": False, "reason": "evidence_audit_failed",
                    "error_type": type(exc).__name__}
    return {"schema": SCHEMA, "ready": bool(anchor.get("ready")) and bool(evidence.get("valid")),
            "checked_at": current.isoformat(), "environment": environment,
            "approval_reference": approval_reference,
            "checks": {"anchor_recovery": bool(anchor.get("ready")),
                       "evidence_integrity": bool(evidence.get("valid"))},
            "details": {"anchor": anchor, "evidence": evidence},
            "limitations": "Read-only provider responses; no deletion-denial, independent custody, or clinical proof"}
