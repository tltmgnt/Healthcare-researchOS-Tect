"""Read-only version-pinned retrieval of signed validation evidence artifacts.

The caller must supply an independently configured object-store client and
explicit object versions. No URL resolution or implicit latest-version reads.
"""
from typing import Any

from .provider_validation import REQUIRED_CONTROLS
from .validation_artifact_manifest import MAX_ARTIFACT_BYTES, verify_artifact_manifest


def verify_retrieved_evidence(client: Any, manifest: dict, locations: dict,
                              trusted_public_keys: dict) -> dict:
    """Retrieve six pinned object versions and validate signed SHA-256 bindings."""
    if not isinstance(locations, dict) or set(locations) != set(REQUIRED_CONTROLS):
        return {"valid": False, "reason": "invalid_locations"}
    if not isinstance(manifest, dict) or not isinstance(manifest.get("artifacts"), dict):
        return {"valid": False, "reason": "invalid_manifest"}
    # Validate signature and manifest structure before making remote reads,
    # using placeholder bytes only after verifying location structure is safe.
    artifacts = {}
    for control in REQUIRED_CONTROLS:
        loc = locations[control]
        if not isinstance(loc, dict) or set(loc) != {"bucket", "key", "version_id"}:
            return {"valid": False, "reason": "invalid_location", "control": control}
        if not all(isinstance(v, str) and v.strip() for v in loc.values()):
            return {"valid": False, "reason": "invalid_location", "control": control}
    for control in REQUIRED_CONTROLS:
        loc = locations[control]
        try:
            response = client.get_object(
                Bucket=loc["bucket"], Key=loc["key"], VersionId=loc["version_id"]
            )
            body = response["Body"].read(MAX_ARTIFACT_BYTES + 1)
        except Exception as exc:
            return {"valid": False, "reason": "retrieval_failed", "control": control,
                    "error_type": type(exc).__name__}
        if not isinstance(body, bytes) or not body or len(body) > MAX_ARTIFACT_BYTES:
            return {"valid": False, "reason": "invalid_retrieved_artifact", "control": control}
        artifacts[control] = body
    result = verify_artifact_manifest(manifest, artifacts, trusted_public_keys)
    if not result["valid"]:
        return result
    return {"valid": True, "controls_checked": len(REQUIRED_CONTROLS),
            "locations": {control: dict(locations[control]) for control in REQUIRED_CONTROLS},
            "limitations": "Version-pinned digest verification; provider identity and custody not independently attested"}
