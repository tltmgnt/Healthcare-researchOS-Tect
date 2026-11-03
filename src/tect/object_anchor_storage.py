"""S3-compatible signed anchor publication with conditional creation.

Requires an independently administered bucket with Object Lock configured
outside this library. Passing an S3 client allows use without a boto3 dependency.
"""
import hashlib
import json
from typing import Any

from .historical_audit import verify_historical_signed_checkpoint


def _serialize(envelope: dict) -> bytes:
    return (json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def publish_anchor(client: Any, bucket: str, key: str, envelope: dict) -> dict:
    """Upload a signed envelope once; refuse an existing object key."""
    if not bucket or not key or not isinstance(envelope, dict):
        raise ValueError("bucket, key and envelope required")
    data = _serialize(envelope)
    digest = hashlib.sha256(data).hexdigest()
    # S3 IfNoneMatch='*' makes a create conditional; the storage service must
    # support and enforce it. Object Lock retention is configured externally.
    response = client.put_object(
        Bucket=bucket, Key=key, Body=data, ContentType="application/json",
        IfNoneMatch="*", Metadata={"sha256": digest},
    )
    return {"bucket": bucket, "key": key, "sha256": digest,
            "version_id": response.get("VersionId")}


def retrieve_and_verify_anchor(client: Any, bucket: str, key: str, trusted_public_keys: dict,
                               *, expected_sha256: str, version_id: str | None = None) -> dict:
    """Verify retrieved object bytes and signed historical audit checkpoint."""
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        return {"valid": False, "reason": "invalid_expected_digest"}
    params = {"Bucket": bucket, "Key": key}
    if version_id is not None:
        params["VersionId"] = version_id
    try:
        response = client.get_object(**params)
        body = response["Body"].read()
        if not isinstance(body, bytes):
            return {"valid": False, "reason": "invalid_object"}
        if hashlib.sha256(body).hexdigest() != expected_sha256:
            return {"valid": False, "reason": "object_digest_mismatch"}
        envelope = json.loads(body.decode("utf-8"))
    except (OSError, ValueError, KeyError, UnicodeError):
        return {"valid": False, "reason": "invalid_object"}
    return verify_historical_signed_checkpoint(envelope, trusted_public_keys)
