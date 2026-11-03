"""Read-only version-pinned S3 retrieval of independently signed floor anchors.

Provider enforcement, retention and account independence require live tests.
"""
import json
from datetime import datetime

from .external_floor_anchors import verify_floor_anchor, verify_local_floor_against_anchor
from .durable_registry_floor import RegistryFloorStore

SCHEMA = "tect.independent-floor-object-verification.v1"
MAX_BYTES = 64 * 1024


def verify_pinned_floor_object(storage_client, identity_client, *,
                               bucket: str, key: str, version_id: str,
                               approved_account_id: str, approved_buckets: set[str],
                               trusted_authorities: dict,
                               independently_pinned_sequence: int,
                               checked_at: datetime, approval_reference: str,
                               enabled: bool = False, environment: str = "",
                               local_store: RegistryFloorStore | None = None) -> dict:
    """Fail closed before any cloud call unless explicit approval is present."""
    def denied(reason: str) -> dict:
        return {"schema": SCHEMA, "ready": False, "reason": reason}
    if enabled is not True:
        return denied("explicit_opt_in_required")
    if environment != "non-production":
        return denied("non_production_only")
    if not isinstance(approval_reference, str) or not approval_reference.strip():
        return denied("approval_required")
    if not isinstance(approved_account_id, str) or not approved_account_id.isdigit() or len(approved_account_id) != 12:
        return denied("invalid_approved_account")
    if not isinstance(approved_buckets, (set, frozenset)) or not approved_buckets:
        return denied("approved_buckets_required")
    if not isinstance(bucket, str) or bucket not in approved_buckets:
        return denied("bucket_not_approved")
    if not all(isinstance(x, str) and x.strip() for x in (key, version_id)):
        return denied("version_pinned_object_required")
    if not isinstance(checked_at, datetime) or checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")
    if type(independently_pinned_sequence) is not int or independently_pinned_sequence < 1:
        raise ValueError("Independently pinned sequence required")
    if local_store is not None and not isinstance(local_store, RegistryFloorStore):
        raise ValueError("Invalid local floor store")
    try:
        identity = identity_client.get_caller_identity()
        if not isinstance(identity, dict) or identity.get("Account") != approved_account_id:
            return denied("account_not_approved")
        response = storage_client.get_object(Bucket=bucket, Key=key, VersionId=version_id)
        if not isinstance(response, dict) or response.get("VersionId") != version_id:
            return denied("object_version_mismatch")
        body = response["Body"]
        try:
            raw = body.read(MAX_BYTES + 1)
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BYTES:
            return denied("invalid_or_oversize_anchor")
        envelope = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, AttributeError):
        return denied("retrieval_or_parse_failed")
    except Exception:
        return denied("provider_read_failed")
    if local_store is not None:
        result = verify_local_floor_against_anchor(
            local_store, envelope, trusted_authorities,
            independently_pinned_sequence=independently_pinned_sequence,
            checked_at=checked_at)
        if not result["ready"]:
            return denied(result["reason"])
        sequence = result["anchor_sequence"]
    else:
        result = verify_floor_anchor(
            envelope, trusted_authorities,
            independently_pinned_sequence=independently_pinned_sequence,
            checked_at=checked_at)
        if not result["valid"]:
            return denied(result["reason"])
        sequence = result["minimum_sequence"]
    return {"schema": SCHEMA, "ready": True, "anchor_sequence": sequence,
            "bucket": bucket, "key": key, "version_id": version_id,
            "approval_reference": approval_reference,
            "limitations": "Read-only verification; does not prove Object Lock retention, IAM deny enforcement, independent custody or latest external pin"}
