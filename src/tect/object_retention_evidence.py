"""Read-only per-version Object Lock retention evidence for published anchors.

A successful inspection is a point-in-time provider report, not a deletion test.
"""
from datetime import datetime, timezone
from typing import Any


def inspect_anchor_retention(client: Any, bucket: str, key: str, version_id: str, *,
                             minimum_remaining_days: int = 365,
                             now: datetime | None = None) -> dict:
    """Require explicit object version and COMPLIANCE retention through minimum horizon."""
    if not all(isinstance(v, str) and v.strip() for v in (bucket, key, version_id)):
        raise ValueError("Nonempty bucket, key and version_id required")
    if type(minimum_remaining_days) is not int or minimum_remaining_days < 1:
        raise ValueError("Positive minimum_remaining_days required")
    current = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("Timezone-aware now required")
    try:
        result = client.get_object_retention(Bucket=bucket, Key=key, VersionId=version_id)
        retention = result.get("Retention", {})
        mode = retention.get("Mode")
        until = retention.get("RetainUntilDate")
        if not isinstance(until, datetime) or until.tzinfo is None or until.utcoffset() is None:
            return {"ready": False, "reason": "invalid_retention_date"}
        remaining_seconds = (until - current).total_seconds()
        checks = {"compliance_mode": mode == "COMPLIANCE",
                  "retention_sufficient": remaining_seconds >= minimum_remaining_days * 86400}
        return {"ready": all(checks.values()), "checks": checks,
                "bucket": bucket, "key": key, "version_id": version_id,
                "retain_until": until.isoformat(), "checked_at": current.isoformat(),
                "minimum_remaining_days": minimum_remaining_days,
                "note": "Provider-reported version retention only; no deletion or custody proof"}
    except Exception as exc:
        return {"ready": False, "reason": "retention_inspection_failed",
                "error_type": type(exc).__name__}
