"""Fail-closed provider identity and bucket allowlist gate for read-only audits.

Caller-supplied policy must be independently approved. This checks identity
reported by STS, not whether credentials have read-only IAM permissions.
"""
import re
from typing import Any

from .provider_integration_readiness import run_readonly_provider_validation

_ACCOUNT = re.compile(r"^[0-9]{12}$")
SCHEMA = "tect.provider-target-approval.v1"


def run_approved_provider_validation(storage_client: Any, identity_client: Any, *,
                                     approved_account_id: str,
                                     approved_buckets: set[str],
                                     **validation_args) -> dict:
    """Reject unapproved account or buckets before any object-store calls."""
    def denied(reason: str) -> dict:
        return {"ready": False, "schema": SCHEMA, "reason": reason}

    if validation_args.get("enabled") is not True:
        return denied("explicit_opt_in_required")
    if validation_args.get("environment") != "non-production":
        return denied("non_production_only")
    approval = validation_args.get("approval_reference")
    if not isinstance(approval, str) or not approval.strip():
        return denied("approval_reference_required")
    if not isinstance(approved_account_id, str) or not _ACCOUNT.fullmatch(approved_account_id):
        return denied("invalid_approved_account")
    if (not isinstance(approved_buckets, (set, frozenset)) or not approved_buckets
            or any(not isinstance(b, str) or not b.strip() for b in approved_buckets)):
        return denied("invalid_approved_buckets")
    anchor_bucket = validation_args.get("anchor_bucket")
    locations = validation_args.get("evidence_locations")
    if not isinstance(anchor_bucket, str) or anchor_bucket not in approved_buckets:
        return denied("unapproved_anchor_bucket")
    if not isinstance(locations, dict) or not locations:
        return denied("invalid_evidence_locations")
    for control, location in locations.items():
        if (not isinstance(location, dict)
                or not isinstance(location.get("bucket"), str)
                or location["bucket"] not in approved_buckets):
            return denied("unapproved_evidence_bucket")
    try:
        identity = identity_client.get_caller_identity()
    except Exception as exc:
        return {**denied("identity_lookup_failed"), "error_type": type(exc).__name__}
    if not isinstance(identity, dict) or identity.get("Account") != approved_account_id:
        return denied("account_mismatch")
    result = run_readonly_provider_validation(storage_client, **validation_args)
    return {**result, "target_approval": {"schema": SCHEMA,
            "account_id": approved_account_id,
            "approved_buckets": sorted(approved_buckets),
            "identity_checked": True},
            "limitations": "STS account check and allowlist only; IAM permissions, endpoint authenticity and independent custody not proven"}
