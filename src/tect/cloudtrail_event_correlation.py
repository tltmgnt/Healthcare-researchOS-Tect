"""Strict structural validation of AWS CloudTrail-style deletion-denial events.

CloudTrail-shaped JSON is NOT authenticated CloudTrail provenance. An
independent CloudTrail digest-chain and AWS signature verification is required.
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone

SCHEMA = "tect.cloudtrail-event-correlation.v1"
MAX_BYTES = 2 * 1024 * 1024


def validate_cloudtrail_denial(raw: bytes, *, expected_account_id: str,
                               expected_bucket: str, expected_key: str,
                               expected_version_id: str, expected_request_id: str,
                               checked_at: datetime, max_age_days: int = 90,
                               expected_sha256: str | None = None) -> dict:
    def denied(reason):
        return {"schema": SCHEMA, "valid": False, "reason": reason}
    if not isinstance(checked_at, datetime) or checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")
    if type(max_age_days) is not int or not 1 <= max_age_days <= 365:
        raise ValueError("Invalid max_age_days")
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BYTES:
        return denied("invalid_or_oversize_log")
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        return denied("log_digest_mismatch")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        return denied("invalid_json")
    if not isinstance(document, dict) or set(document) != {"Records"}:
        return denied("invalid_log_envelope")
    records = document["Records"]
    if not isinstance(records, list) or not 1 <= len(records) <= 1000:
        return denied("invalid_record_count")
    matching = []
    for record in records:
        if not isinstance(record, dict):
            return denied("invalid_record")
        if (record.get("eventSource") != "s3.amazonaws.com"
                or record.get("eventName") != "DeleteObject"
                or record.get("errorCode") not in ("AccessDenied", "AccessDeniedException")
                or record.get("recipientAccountId") != expected_account_id
                or record.get("requestID") != expected_request_id):
            continue
        params = record.get("requestParameters")
        if not isinstance(params, dict):
            continue
        if (params.get("bucketName") != expected_bucket
                or params.get("key") != expected_key
                or params.get("versionId") != expected_version_id):
            continue
        try:
            event_time = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
            if event_time.tzinfo is None or event_time.utcoffset() is None:
                return denied("invalid_event_time")
            age = checked_at.astimezone(timezone.utc) - event_time.astimezone(timezone.utc)
        except (ValueError, TypeError, KeyError, AttributeError):
            return denied("invalid_event_time")
        if age < timedelta(0) or age > timedelta(days=max_age_days):
            return denied("stale_or_future_event")
        matching.append(record)
    if len(matching) != 1:
        return denied("unique_matching_denial_required")
    return {"schema": SCHEMA, "valid": True, "request_id": expected_request_id,
            "log_sha256": digest, "matched_records": 1,
            "limitations": "CloudTrail-shaped event only; provider authenticity, digest chain and AWS signature not verified"}


def correlate_provider_denial(normalized_audit_result: dict, cloudtrail_raw: bytes, *,
                              expected_account_id: str, expected_bucket: str,
                              expected_key: str, expected_version_id: str,
                              checked_at: datetime, expected_cloudtrail_sha256: str) -> dict:
    """Require Phase 40 success and exact request-ID correlation."""
    if not isinstance(normalized_audit_result, dict) or normalized_audit_result.get("ready") is not True:
        return {"schema": SCHEMA, "valid": False, "reason": "phase40_audit_not_ready"}
    if normalized_audit_result.get("schema") != "tect.provider-audit-evidence.v1":
        return {"schema": SCHEMA, "valid": False, "reason": "phase40_schema_mismatch"}
    if normalized_audit_result.get("protected_version_id") != expected_version_id:
        return {"schema": SCHEMA, "valid": False, "reason": "protected_version_mismatch"}
    request_id = normalized_audit_result.get("request_id")
    if not isinstance(request_id, str) or not request_id.strip():
        return {"schema": SCHEMA, "valid": False, "reason": "missing_request_id"}
    return validate_cloudtrail_denial(
        cloudtrail_raw, expected_account_id=expected_account_id,
        expected_bucket=expected_bucket, expected_key=expected_key,
        expected_version_id=expected_version_id, expected_request_id=request_id,
        checked_at=checked_at, expected_sha256=expected_cloudtrail_sha256)
