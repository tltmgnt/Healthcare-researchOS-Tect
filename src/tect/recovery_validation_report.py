"""Combined read-only recovery assurance and signed IAM evidence report.

The report requires independent reviewer trust and approved target checks.
No cloud operations occur without explicit opt-in and non-production approval.
"""
from datetime import datetime, timezone
from typing import Any

from .approved_provider_targets import run_approved_provider_validation
from .provider_policy_evidence import verify_policy_assessment

SCHEMA = "tect.recovery-validation-report.v1"


def generate_recovery_validation_report(storage_client: Any, identity_client: Any, *,
                                        policy_envelope: dict, policy_report: bytes,
                                        trusted_reviewer_keys: dict,
                                        approved_account_id: str, approved_buckets: set[str],
                                        checked_at: datetime | None = None,
                                        **validation_args) -> dict:
    """Combine a trusted policy assessment with approved read-only recovery checks."""
    def denied(reason: str, **extra) -> dict:
        return {"schema": SCHEMA, "ready": False, "reason": reason, **extra}

    # Avoid even an identity lookup unless the operator has explicitly opted in.
    if validation_args.get("enabled") is not True:
        return denied("explicit_opt_in_required")
    if validation_args.get("environment") != "non-production":
        return denied("non_production_only")
    approval = validation_args.get("approval_reference")
    if not isinstance(approval, str) or not approval.strip():
        return denied("approval_reference_required")
    current = checked_at if checked_at is not None else datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")

    policy = verify_policy_assessment(
        policy_envelope, policy_report, trusted_reviewer_keys,
        expected_account_id=approved_account_id,
        expected_approval_reference=approval,
    )
    if not policy["valid"]:
        return denied("policy_assessment_invalid", policy=policy,
                      checked_at=current.isoformat())
    provider = run_approved_provider_validation(
        storage_client, identity_client,
        approved_account_id=approved_account_id, approved_buckets=approved_buckets,
        checked_at=current, **validation_args
    )
    return {"schema": SCHEMA, "ready": bool(provider.get("ready")),
            "checked_at": current.isoformat(), "approval_reference": approval,
            "account_id": approved_account_id,
            "checks": {"signed_policy_assessment": True,
                       "approved_provider_recovery": bool(provider.get("ready"))},
            "details": {"policy": policy, "provider": provider},
            "limitations": "Signed reviewer assertions and read-only provider reports; not live enforcement, independent custody or clinical proof"}
