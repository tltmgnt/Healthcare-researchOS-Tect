"""Read-only provider retention assurance for a version-pinned floor anchor.

This checks provider-reported metadata; it does not attempt deletion or
prove effective IAM enforcement or independent storage custody.
"""
from datetime import datetime, timezone

from .independent_floor_object_verification import verify_pinned_floor_object

SCHEMA = "tect.floor-anchor-retention-assurance.v1"


def verify_retained_floor_anchor(storage_client, identity_client, *,
                                 bucket: str, key: str, version_id: str,
                                 approved_account_id: str, approved_buckets: set[str],
                                 trusted_authorities: dict,
                                 independently_pinned_sequence: int,
                                 checked_at: datetime, approval_reference: str,
                                 minimum_retention_days: int = 30,
                                 enabled: bool = False, environment: str = "",
                                 local_store=None) -> dict:
    """Verify signed anchor, version-specific COMPLIANCE retention and hold."""
    def denied(reason, **details):
        return {"schema": SCHEMA, "ready": False, "reason": reason, **details}
    if type(minimum_retention_days) is not int or not 1 <= minimum_retention_days <= 3650:
        raise ValueError("Retention threshold must be 1..3650 days")
    # Phase 37 validates opt-in, account, bucket, and version before cloud access.
    anchor = verify_pinned_floor_object(
        storage_client, identity_client, bucket=bucket, key=key,
        version_id=version_id, approved_account_id=approved_account_id,
        approved_buckets=approved_buckets, trusted_authorities=trusted_authorities,
        independently_pinned_sequence=independently_pinned_sequence,
        checked_at=checked_at, approval_reference=approval_reference,
        enabled=enabled, environment=environment, local_store=local_store)
    if not anchor["ready"]:
        return denied("anchor_verification_failed", anchor=anchor)
    try:
        retention = storage_client.get_object_retention(
            Bucket=bucket, Key=key, VersionId=version_id)
        hold = storage_client.get_object_legal_hold(
            Bucket=bucket, Key=key, VersionId=version_id)
    except Exception:
        return denied("retention_metadata_read_failed")
    if not isinstance(retention, dict) or not isinstance(hold, dict):
        return denied("invalid_provider_metadata")
    if retention.get("VersionId", version_id) != version_id or hold.get("VersionId", version_id) != version_id:
        return denied("retention_version_mismatch")
    record = retention.get("Retention")
    legal = hold.get("LegalHold")
    if not isinstance(record, dict) or not isinstance(legal, dict):
        return denied("missing_retention_or_hold")
    if record.get("Mode") != "COMPLIANCE":
        return denied("compliance_mode_required")
    until = record.get("RetainUntilDate")
    if not isinstance(until, datetime) or until.tzinfo is None or until.utcoffset() is None:
        return denied("invalid_retention_date")
    if until.astimezone(timezone.utc) < checked_at.astimezone(timezone.utc):
        return denied("retention_expired")
    remaining_seconds = (until - checked_at).total_seconds()
    if remaining_seconds < minimum_retention_days * 86400:
        return denied("retention_below_threshold")
    if legal.get("Status") != "ON":
        return denied("legal_hold_required")
    return {"schema": SCHEMA, "ready": True, "anchor_sequence": anchor["anchor_sequence"],
            "version_id": version_id, "retention_mode": "COMPLIANCE",
            "retain_until": until.isoformat(), "legal_hold": "ON",
            "minimum_retention_days": minimum_retention_days,
            "limitations": "Provider-reported read-only metadata only; no deletion-denial proof, effective IAM attestation or independent custody proof"}
