"""Offline, explicitly pinned CloudTrail-style digest chain continuity.

This verifies a local SHA-256 chain convention. It is not a substitute
for AWS's published digest hash/signature canonicalization.
"""
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

SCHEMA = "tect.cloudtrail-digest-chain-preflight.v1"
MAX_DIGEST_BYTES = 2 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timezone required")
    return parsed.astimezone(timezone.utc)


def verify_pinned_digest_chain(digests: list, *, expected_paths: list[str],
                               expected_sha256: list[str],
                               trusted_initial_previous_hash: str,
                               checked_at: datetime,
                               max_age_days: int = 90) -> dict:
    """Verify pinned, ordered digest bytes and explicit predecessor hashes.

    Each digest must declare digestStartTime, digestEndTime,
    previousDigestHashValue and previousDigestS3Object. The predecessor
    hash is checked against SHA-256 of the prior raw digest bytes.
    """
    def denied(reason):
        return {"schema": SCHEMA, "valid": False, "reason": reason}
    if not isinstance(checked_at, datetime) or checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ValueError("Timezone-aware checked_at required")
    if type(max_age_days) is not int or not 1 <= max_age_days <= 365:
        raise ValueError("Invalid age policy")
    if (not isinstance(digests, list) or not 2 <= len(digests) <= 100
            or not isinstance(expected_paths, list) or len(expected_paths) != len(digests)
            or not isinstance(expected_sha256, list) or len(expected_sha256) != len(digests)):
        return denied("invalid_chain_length")
    if (not isinstance(trusted_initial_previous_hash, str)
            or not SHA256.fullmatch(trusted_initial_previous_hash)):
        return denied("invalid_initial_pin")
    if (len(set(expected_paths)) != len(expected_paths)
            or any(not isinstance(path, str) or not path.strip() for path in expected_paths)
            or any(not isinstance(digest, str) or not SHA256.fullmatch(digest)
                   for digest in expected_sha256)):
        return denied("invalid_expected_pins")
    prior_end = None
    prior_hash = trusted_initial_previous_hash
    prior_path = None
    for index, raw in enumerate(digests):
        if not isinstance(raw, bytes) or not raw or len(raw) > MAX_DIGEST_BYTES:
            return denied("invalid_digest_bytes")
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != expected_sha256[index]:
            return denied("digest_pin_mismatch")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError):
            return denied("invalid_digest_json")
        if not isinstance(document, dict):
            return denied("invalid_digest_document")
        if document.get("digestS3Object") != expected_paths[index]:
            return denied("digest_path_mismatch")
        if document.get("previousDigestHashValue") != prior_hash:
            return denied("predecessor_hash_mismatch")
        if index and document.get("previousDigestS3Object") != prior_path:
            return denied("predecessor_path_mismatch")
        try:
            start = _timestamp(document.get("digestStartTime"))
            end = _timestamp(document.get("digestEndTime"))
        except (ValueError, TypeError):
            return denied("invalid_interval")
        if end <= start:
            return denied("invalid_interval")
        if prior_end is not None and start != prior_end:
            return denied("noncontiguous_interval")
        age = checked_at.astimezone(timezone.utc) - end
        if age < timedelta(0) or age > timedelta(days=max_age_days):
            return denied("stale_or_future_digest")
        prior_hash, prior_path, prior_end = actual_hash, expected_paths[index], end
    return {"schema": SCHEMA, "valid": True, "digest_count": len(digests),
            "final_digest_sha256": prior_hash, "final_path": prior_path,
            "limitations": "Offline SHA-256 predecessor checks only; AWS canonical digest hashing, signed-message verification, key provenance and live custody not established"}
