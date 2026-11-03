"""Read-only recovery assurance report for externally retained composite anchors.

Reports provider configuration and signature/history checks; does not certify
independent custody, enforcement of retention, or production readiness.
"""
from datetime import datetime, timezone
from typing import Any

from .composite_object_storage import retrieve_and_verify_composite_anchor
from .object_lock_assurance import inspect_anchor_bucket
from .object_retention_evidence import inspect_anchor_retention


def audit_composite_anchor_recovery(client: Any, bucket: str, key: str, version_id: str,
                                    trusted_public_keys: dict, *, expected_sha256: str,
                                    minimum_retention_days: int = 365,
                                    now: datetime | None = None) -> dict:
    """Fail closed and report independent checks for a specific anchor version."""
    checked_at = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(checked_at, datetime) or checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("Timezone-aware now required")
    if not all(isinstance(v, str) and v.strip() for v in (bucket, key, version_id)):
        raise ValueError("Nonempty bucket, key and version_id required")
    if type(minimum_retention_days) is not int or minimum_retention_days < 1:
        raise ValueError("Positive minimum_retention_days required")

    bucket_check = inspect_anchor_bucket(client, bucket, minimum_retention_days=minimum_retention_days)
    retention_check = inspect_anchor_retention(
        client, bucket, key, version_id, minimum_remaining_days=minimum_retention_days, now=checked_at
    )
    try:
        anchor_check = retrieve_and_verify_composite_anchor(
            client, bucket, key, trusted_public_keys,
            expected_sha256=expected_sha256, version_id=version_id
        )
    except Exception as exc:
        anchor_check = {"valid": False, "reason": "anchor_retrieval_failed",
                        "error_type": type(exc).__name__}
    checks = {"bucket_configuration": bool(bucket_check.get("ready")),
              "object_version_retention": bool(retention_check.get("ready")),
              "anchor_integrity_and_history": bool(anchor_check.get("valid"))}
    return {"ready": all(checks.values()), "checked_at": checked_at.isoformat(),
            "bucket": bucket, "key": key, "version_id": version_id,
            "expected_sha256": expected_sha256,
            "checks": checks,
            "details": {"bucket": bucket_check, "retention": retention_check, "anchor": anchor_check},
            "limitations": "Read-only provider reports; no deletion denial, independent custody, or clinical validation"}
