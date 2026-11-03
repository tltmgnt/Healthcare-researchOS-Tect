"""Content-addressed evidence provenance snapshots for versioned claims.

These records establish integrity of supplied text, not source authenticity.
"""
import hashlib
import json
from datetime import datetime, timezone

from .storage import canonical, connect, sha256


def _snapshot(claim_id: str, version: int, payload: str) -> dict:
    claim = json.loads(payload)
    records = []
    for item in claim.get("evidence", []):
        material = {key: item[key] for key in ("id", "source", "locator", "excerpt", "relation")}
        records.append({
            "evidence_id": material["id"],
            "source": material["source"],
            "locator": material["locator"],
            "content_sha256": sha256(canonical(material)),
        })
    return {"schema": "tect.evidence-provenance.v1", "claim_id": claim_id,
            "claim_version": version, "claim_payload_sha256": sha256(payload),
            "evidence": records}


def capture_provenance(claim_id: str, version: int) -> dict:
    """Persist a provenance snapshot for an existing immutable claim version."""
    if not claim_id or type(version) is not int or version < 1:
        raise ValueError("Valid claim ID and version required")
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("CREATE TABLE IF NOT EXISTS evidence_provenance (claim_id TEXT NOT NULL, version INTEGER NOT NULL, manifest TEXT NOT NULL, manifest_sha256 TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(claim_id, version))")
        row = db.execute("SELECT payload FROM claims WHERE id=? AND version=?", (claim_id, version)).fetchone()
        if row is None:
            raise ValueError("Claim version not found")
        snapshot = _snapshot(claim_id, version, row[0])
        manifest = canonical(snapshot)
        digest = sha256(manifest)
        existing = db.execute("SELECT manifest, manifest_sha256 FROM evidence_provenance WHERE claim_id=? AND version=?", (claim_id, version)).fetchone()
        if existing is not None:
            if existing != (manifest, digest):
                raise ValueError("Existing provenance record conflicts with claim")
        else:
            db.execute("INSERT INTO evidence_provenance VALUES (?, ?, ?, ?, ?)",
                       (claim_id, version, manifest, digest, datetime.now(timezone.utc).isoformat()))
        db.commit()
    return {**snapshot, "manifest_sha256": digest}


def verify_provenance(claim_id: str, version: int) -> dict:
    with connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS evidence_provenance (claim_id TEXT NOT NULL, version INTEGER NOT NULL, manifest TEXT NOT NULL, manifest_sha256 TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(claim_id, version))")
        record = db.execute("SELECT manifest, manifest_sha256 FROM evidence_provenance WHERE claim_id=? AND version=?", (claim_id, version)).fetchone()
        claim = db.execute("SELECT payload FROM claims WHERE id=? AND version=?", (claim_id, version)).fetchone()
        if record is None or claim is None:
            return {"valid": False, "reason": "missing_provenance_or_claim"}
        expected = canonical(_snapshot(claim_id, version, claim[0]))
        if record[0] != expected or sha256(record[0]) != record[1]:
            return {"valid": False, "reason": "provenance_mismatch"}
        return {"valid": True, "claim_id": claim_id, "version": version,
                "evidence_checked": len(json.loads(record[0])["evidence"])}
