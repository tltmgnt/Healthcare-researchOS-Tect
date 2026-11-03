"""Opt-in S3-compatible composite anchor publication and retrieval.

Immutable storage and independent key custody are operator responsibilities.
"""
import hashlib
import hmac
import json
import re
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .composite_anchors import sign_composite_anchor, verify_composite_anchor
from .storage import canonical

MAX_BYTES = 64 * 1024
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def publish_composite_anchor(client: Any, bucket: str, key: str,
                             private_key: Ed25519PrivateKey, key_id: str) -> dict:
    """Sign both current histories and conditionally create an object."""
    if not isinstance(bucket, str) or not bucket.strip() or not isinstance(key, str) or not key.strip():
        raise ValueError("Nonempty bucket and key required")
    envelope = sign_composite_anchor(private_key, key_id)
    body = (canonical(envelope) + "\n").encode("utf-8")
    if len(body) > MAX_BYTES:
        raise ValueError("Composite anchor exceeds size limit")
    digest = hashlib.sha256(body).hexdigest()
    response = client.put_object(
        Bucket=bucket, Key=key, Body=body, ContentType="application/json",
        IfNoneMatch="*", Metadata={"sha256": digest},
    )
    return {"bucket": bucket, "key": key, "sha256": digest,
            "version_id": response.get("VersionId")}


def retrieve_and_verify_composite_anchor(client: Any, bucket: str, key: str,
                                         trusted_public_keys: dict, *,
                                         expected_sha256: str,
                                         version_id: str | None = None) -> dict:
    """Check independently supplied digest and Ed25519-signed historical heads."""
    if not isinstance(expected_sha256, str) or not _DIGEST.fullmatch(expected_sha256):
        return {"valid": False, "reason": "invalid_expected_digest"}
    if not isinstance(bucket, str) or not bucket or not isinstance(key, str) or not key:
        return {"valid": False, "reason": "invalid_object_location"}
    params = {"Bucket": bucket, "Key": key}
    if version_id is not None:
        params["VersionId"] = version_id
    try:
        response = client.get_object(**params)
        body = response["Body"].read(MAX_BYTES + 1)
        if not isinstance(body, bytes):
            return {"valid": False, "reason": "invalid_object"}
        if len(body) > MAX_BYTES:
            return {"valid": False, "reason": "object_too_large"}
        if not hmac.compare_digest(hashlib.sha256(body).hexdigest(), expected_sha256):
            return {"valid": False, "reason": "object_digest_mismatch"}
        envelope = json.loads(body.decode("utf-8"))
    except (OSError, KeyError, ValueError, UnicodeError):
        return {"valid": False, "reason": "invalid_object"}
    return verify_composite_anchor(envelope, trusted_public_keys)
