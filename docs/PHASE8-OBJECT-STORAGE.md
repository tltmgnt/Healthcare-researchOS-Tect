# Phase 8 — S3-compatible anchor storage adapter

`tect.object_anchor_storage` publishes signed checkpoint envelopes using
conditional object creation (`IfNoneMatch="*"`) and retrieves them by bucket,
key and optional version ID. It checks a separately recorded SHA-256 digest
before verifying the Ed25519 signature and historical audit prefix.

```python
import boto3  # optional application dependency
from tect.object_anchor_storage import publish_anchor, retrieve_and_verify_anchor

client = boto3.client("s3")
receipt = publish_anchor(client, "independent-audit-bucket", "anchors/001.json", envelope)
result = retrieve_and_verify_anchor(
    client, receipt["bucket"], receipt["key"], trusted_public_keys,
    expected_sha256=receipt["sha256"], version_id=receipt["version_id"],
)
```

**Production setup is external:** Configure a separately administered S3
bucket with Object Lock in compliance mode, versioning, restricted write/delete
IAM permissions, retention, independent custody of the receipt digest and
trusted verification keys, and monitoring. This code does not configure or
attest any of those protections. Some S3-compatible providers do not support
conditional writes or Object Lock; validate provider behavior before use.
The returned digest must be retained outside the same compromised trust domain.

This adapter has no live cloud integration tests and no proof of remote
immutability. Object retrieval errors from the provider propagate to the caller.
It does not implement evidence provenance, timestamp attestations or clinical
validation. The `boto3` SDK is optional and is not installed by this package.
