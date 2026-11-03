"""Read-only independent retrieval and cross-check of provider audit evidence.

The audit record is a normalized evidence artifact, not a provider-authenticated
CloudTrail event. Provenance and real-world deletion denial require external review.
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone

from .independent_custody_evidence import verify_custody_assessment

SCHEMA = "tect.provider-audit-evidence.v1"
MAX_BYTES = 2 * 1024 * 1024
AUDIT_CONTROL = "protected_version_deletion_denied"


def verify_independent_provider_audit(storage_client, identity_client, *,
                                      audit_bucket: str, audit_key: str,
                                      audit_version_id: str, approved_audit_buckets: set,
                                      approved_audit_account_id: str,
                                      protected_account_id: str, protected_bucket: str,
                                      protected_key: str, protected_version_id: str,
                                      expected_operator_id: str, assessment_envelope: dict,
                                      assessment_artifacts: dict, trusted_assessors: dict,
                                      checked_at: datetime, approval_reference: str,
                                      enabled: bool = False, environment: str = "") -> dict:
    """Require independent account, signed artifact digest and denied audit event."""
    def denied(reason):
        return {"schema": SCHEMA, "ready": False, "reason": reason}
    if enabled is not True:
        return denied("explicit_opt_in_required")
    if environment != "non-production":
        return denied("non_production_only")
    if not isinstance(approval_reference, str) or not approval_reference.strip():
        return denied("approval_required")
    if not all(isinstance(a, str) and len(a) == 12 and a.isdigit()
               for a in (approved_audit_account_id, protected_account_id)):
        return denied("invalid_account")
    if approved_audit_account_id == protected_account_id:
        return denied("independent_account_required")
    if (not isinstance(approved_audit_buckets, (set, frozenset))
            or not isinstance(audit_bucket, str) or audit_bucket not in approved_audit_buckets):
        return denied("audit_bucket_not_approved")
    if not all(isinstance(v, str) and v.strip() for v in
               (audit_key, audit_version_id, protected_bucket, protected_key,
                protected_version_id, expected_operator_id)):
        return denied("invalid_target")
    if not isinstance(checked_at, datetime) or checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")
    assessment = verify_custody_assessment(
        assessment_envelope, assessment_artifacts, trusted_assessors,
        expected_account_id=protected_account_id, expected_bucket=protected_bucket,
        expected_key=protected_key, expected_version_id=protected_version_id,
        expected_operator_id=expected_operator_id, checked_at=checked_at)
    if not assessment["valid"]:
        return denied("signed_assessment_invalid")
    try:
        identity = identity_client.get_caller_identity()
        if not isinstance(identity, dict) or identity.get("Account") != approved_audit_account_id:
            return denied("audit_account_not_approved")
        response = storage_client.get_object(
            Bucket=audit_bucket, Key=audit_key, VersionId=audit_version_id)
        if not isinstance(response, dict) or response.get("VersionId") != audit_version_id:
            return denied("audit_version_mismatch")
        body = response["Body"]
        try:
            raw = body.read(MAX_BYTES + 1)
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BYTES:
            return denied("invalid_audit_bytes")
    except Exception:
        return denied("audit_retrieval_failed")
    if hashlib.sha256(raw).hexdigest() != assessment_envelope["payload"]["controls"][AUDIT_CONTROL]["sha256"]:
        return denied("signed_audit_digest_mismatch")
    # A caller-provided artifact and the independently fetched bytes must match exactly.
    if raw != assessment_artifacts[AUDIT_CONTROL]:
        return denied("audit_artifact_mismatch")
    try:
        record = json.loads(raw.decode("utf-8"))
        expected_fields = {"schema", "account_id", "bucket", "key", "version_id",
                           "action", "outcome", "event_time", "request_id", "approval_reference"}
        if not isinstance(record, dict) or set(record) != expected_fields:
            return denied("invalid_audit_record")
        if record["schema"] != SCHEMA:
            return denied("invalid_audit_schema")
        if (record["account_id"] != protected_account_id
                or record["bucket"] != protected_bucket
                or record["key"] != protected_key
                or record["version_id"] != protected_version_id
                or record["approval_reference"] != approval_reference):
            return denied("audit_target_mismatch")
        if record["action"] != "DeleteObjectVersion" or record["outcome"] != "AccessDenied":
            return denied("deletion_denial_not_evidenced")
        if not isinstance(record["request_id"], str) or not record["request_id"].strip():
            return denied("missing_request_id")
        event_time = datetime.fromisoformat(record["event_time"])
        if event_time.tzinfo is None or event_time.utcoffset() is None:
            return denied("invalid_event_time")
        delta = checked_at.astimezone(timezone.utc) - event_time.astimezone(timezone.utc)
        if delta < timedelta(0) or delta > timedelta(days=90):
            return denied("stale_or_future_event")
    except (ValueError, TypeError, KeyError, AttributeError):
        return denied("invalid_audit_record")
    return {"schema": SCHEMA, "ready": True,
            "audit_account_id": approved_audit_account_id,
            "audit_version_id": audit_version_id,
            "protected_version_id": protected_version_id,
            "request_id": record["request_id"],
            "limitations": "Normalized audit artifact and assessor signature do not authenticate provider event provenance or prove effective Object Lock"}
