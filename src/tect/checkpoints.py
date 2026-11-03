"""Export and verify audit head checkpoints against a separately held manifest.

The exported manifest must be kept outside the database trust boundary.
A local export alone is NOT independent anchoring.
"""
import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path

from .storage import verify_audit_chain

SCHEMA = "tect.audit-checkpoint.v1"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def export_checkpoint() -> dict:
    result = verify_audit_chain()
    if not result["valid"]:
        raise ValueError("Audit chain invalid; checkpoint export refused")
    checkpoint = {
        "schema": SCHEMA,
        "events_checked": result["events_checked"],
        "head_hash": result["head_hash"],
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }
    checkpoint["manifest_sha256"] = hashlib.sha256(_canonical(checkpoint).encode()).hexdigest()
    return checkpoint


def verify_checkpoint(checkpoint: dict) -> dict:
    if not isinstance(checkpoint, dict):
        return {"valid": False, "reason": "invalid_manifest"}
    required = {"schema", "events_checked", "head_hash", "exported_at", "manifest_sha256"}
    if set(checkpoint) != required or checkpoint.get("schema") != SCHEMA:
        return {"valid": False, "reason": "invalid_manifest"}
    if (type(checkpoint.get("events_checked")) is not int
            or checkpoint["events_checked"] < 0
            or not isinstance(checkpoint.get("head_hash"), str)
            or len(checkpoint["head_hash"]) != 64
            or any(c not in "0123456789abcdef" for c in checkpoint["head_hash"])
            or not isinstance(checkpoint.get("exported_at"), str)
            or not isinstance(checkpoint.get("manifest_sha256"), str)):
        return {"valid": False, "reason": "invalid_manifest"}
    content = {k: checkpoint[k] for k in required - {"manifest_sha256"}}
    digest = hashlib.sha256(_canonical(content).encode()).hexdigest()
    if not hmac.compare_digest(digest, checkpoint["manifest_sha256"]):
        return {"valid": False, "reason": "manifest_modified"}
    current = verify_audit_chain()
    if not current["valid"]:
        return {"valid": False, "reason": "audit_chain_invalid"}
    # Exact-head verification deliberately fails if legitimate later events are appended.
    if (current["events_checked"] != checkpoint["events_checked"]
            or not hmac.compare_digest(current["head_hash"], checkpoint["head_hash"])):
        return {"valid": False, "reason": "head_mismatch"}
    return {"valid": True, "events_checked": current["events_checked"]}


def write_checkpoint(path: str | Path) -> dict:
    checkpoint = export_checkpoint()
    target = Path(path)
    # Refuse overwriting an existing anchor.
    with target.open("x", encoding="utf-8") as stream:
        stream.write(_canonical(checkpoint) + "\n")
    return checkpoint
