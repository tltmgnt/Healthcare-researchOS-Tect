"""Read-only S3 bucket configuration preflight for composite anchor retention.

This is a point-in-time configuration check, not proof of immutable custody.
"""
from typing import Any


def inspect_anchor_bucket(client: Any, bucket: str, *, minimum_retention_days: int = 365) -> dict:
    """Fail closed unless versioning and COMPLIANCE-mode Object Lock are configured."""
    if not isinstance(bucket, str) or not bucket.strip():
        raise ValueError("Nonempty bucket required")
    if type(minimum_retention_days) is not int or minimum_retention_days < 1:
        raise ValueError("Positive minimum_retention_days required")
    checks = {"versioning_enabled": False, "object_lock_enabled": False,
              "compliance_mode": False, "retention_sufficient": False}
    try:
        versioning = client.get_bucket_versioning(Bucket=bucket)
        checks["versioning_enabled"] = versioning.get("Status") == "Enabled"
        lock = client.get_object_lock_configuration(Bucket=bucket)
        config = lock.get("ObjectLockConfiguration", {})
        checks["object_lock_enabled"] = config.get("ObjectLockEnabled") == "Enabled"
        default = config.get("Rule", {}).get("DefaultRetention", {})
        checks["compliance_mode"] = default.get("Mode") == "COMPLIANCE"
        days = default.get("Days")
        years = default.get("Years")
        if type(days) is int and days > 0 and years is None:
            checks["retention_sufficient"] = days >= minimum_retention_days
        elif type(years) is int and years > 0 and days is None:
            # Conservative conversion: every year has at least 365 days.
            checks["retention_sufficient"] = years * 365 >= minimum_retention_days
    except Exception as exc:
        # SDKs expose provider-specific exception classes; never treat failures as passing.
        return {"ready": False, "checks": checks, "reason": "bucket_inspection_failed",
                "error_type": type(exc).__name__}
    return {"ready": all(checks.values()), "checks": checks,
            "minimum_retention_days": minimum_retention_days,
            "note": "Configuration-only preflight; independent custody and retention enforcement unproven"}
