"""Signed SHA-256 binding of operator attestations to external evidence bytes.

The caller supplies independently retrieved artifact bytes. This module
authenticates their integrity, not their provenance or substantive truth.
"""
import hashlib
import re
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .provider_validation import REQUIRED_CONTROLS
from .signed_validation_evidence import sign_validation_bundle, verify_validation_bundle
from .storage import canonical

SCHEMA = "tect.validation-artifact-manifest.ed25519.v1"
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_HEX = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")


def _artifact_hashes(attestations: dict, artifacts: dict) -> dict:
    if not isinstance(artifacts, dict) or set(artifacts) != set(REQUIRED_CONTROLS):
        raise ValueError("Exactly one artifact required per validation control")
    result = {}
    for control in REQUIRED_CONTROLS:
        reference = attestations[control]["evidence_reference"]
        body = artifacts[control]
        if not isinstance(body, bytes) or not body or len(body) > MAX_ARTIFACT_BYTES:
            raise ValueError("Evidence must be nonempty bytes within size limit")
        result[control] = {"evidence_reference": reference,
                           "sha256": hashlib.sha256(body).hexdigest(),
                           "size_bytes": len(body)}
    return result


def sign_artifact_manifest(attestations: dict, artifacts: dict,
                           private_key: Ed25519PrivateKey, key_id: str,
                           *, signed_at: datetime | None = None) -> dict:
    """Sign both the full operator checklist and exact artifact byte digests."""
    bundle = sign_validation_bundle(attestations, private_key, key_id, signed_at=signed_at)
    entries = _artifact_hashes(bundle["attestations"], artifacts)
    payload = {"schema": SCHEMA, "validation_bundle": bundle, "artifacts": entries}
    return {**payload, "signature_hex": private_key.sign(canonical(payload).encode("utf-8")).hex()}


def verify_artifact_manifest(manifest: dict, artifacts: dict,
                             trusted_public_keys: dict[str, Ed25519PublicKey]) -> dict:
    """Fail closed on invalid signatures, missing files, or changed artifact bytes."""
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "validation_bundle", "artifacts", "signature_hex"} or manifest.get("schema") != SCHEMA:
        return {"valid": False, "reason": "invalid_manifest"}
    bundle = manifest["validation_bundle"]
    bundle_check = verify_validation_bundle(bundle, trusted_public_keys)
    if not bundle_check["valid"]:
        return {"valid": False, "reason": "validation_bundle_invalid", "detail": bundle_check}
    entries = manifest["artifacts"]
    if not isinstance(entries, dict) or set(entries) != set(REQUIRED_CONTROLS):
        return {"valid": False, "reason": "invalid_manifest"}
    for control in REQUIRED_CONTROLS:
        item = entries[control]
        if (not isinstance(item, dict) or set(item) != {"evidence_reference", "sha256", "size_bytes"}
                or item["evidence_reference"] != bundle["attestations"][control]["evidence_reference"]
                or not isinstance(item["sha256"], str) or not _HEX.fullmatch(item["sha256"])
                or type(item["size_bytes"]) is not int
                or not 0 < item["size_bytes"] <= MAX_ARTIFACT_BYTES):
            return {"valid": False, "reason": "invalid_manifest"}
    signature = manifest["signature_hex"]
    if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
        return {"valid": False, "reason": "invalid_signature"}
    key = trusted_public_keys[bundle["key_id"]]
    payload = {k: manifest[k] for k in ("schema", "validation_bundle", "artifacts")}
    try:
        key.verify(bytes.fromhex(signature), canonical(payload).encode("utf-8"))
    except (InvalidSignature, ValueError, TypeError):
        return {"valid": False, "reason": "signature_mismatch"}
    if not isinstance(artifacts, dict) or set(artifacts) != set(REQUIRED_CONTROLS):
        return {"valid": False, "reason": "missing_or_extra_artifacts"}
    for control in REQUIRED_CONTROLS:
        body = artifacts[control]
        if not isinstance(body, bytes) or not body or len(body) > MAX_ARTIFACT_BYTES:
            return {"valid": False, "reason": "invalid_artifact", "control": control}
        item = entries[control]
        if len(body) != item["size_bytes"] or hashlib.sha256(body).hexdigest() != item["sha256"]:
            return {"valid": False, "reason": "artifact_digest_mismatch", "control": control}
    return {"valid": True, "controls_checked": len(REQUIRED_CONTROLS),
            "key_id": bundle["key_id"],
            "limitations": "Digest binding only; source authenticity and live provider controls unverified"}
