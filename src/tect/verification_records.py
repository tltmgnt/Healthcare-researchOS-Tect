"""Append-only, locally hash-chained DOI verification observations.

Records describe what the resolver returned, not whether evidence is true.
"""
from datetime import datetime, timezone

from .doi_verification import verify_evidence_doi
from .storage import canonical, connect, sha256


def _init(db):
    db.execute("""CREATE TABLE IF NOT EXISTS evidence_verification_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        claim_id TEXT NOT NULL, version INTEGER NOT NULL, evidence_id TEXT NOT NULL,
        observed_at TEXT NOT NULL, method TEXT NOT NULL, result_json TEXT NOT NULL,
        claim_payload_sha256 TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL
    )""")


def record_doi_verification(claim_id: str, version: int, evidence_id: str, *, resolver=None) -> dict:
    """Resolve DOI first, then atomically append an observation tied to claim version."""
    result = verify_evidence_doi(claim_id, version, evidence_id, resolver=resolver)
    if result["status"] in ("claim_not_found", "evidence_not_unique_or_missing"):
        raise ValueError(result["status"])
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        _init(db)
        claim = db.execute("SELECT payload FROM claims WHERE id=? AND version=?", (claim_id, version)).fetchone()
        if claim is None:
            raise ValueError("claim_not_found")
        previous_row = db.execute("SELECT event_hash FROM evidence_verification_events ORDER BY seq DESC LIMIT 1").fetchone()
        previous = previous_row[0] if previous_row else "0" * 64
        observed_at = datetime.now(timezone.utc).isoformat()
        event = {
            "claim_id": claim_id, "version": version, "evidence_id": evidence_id,
            "observed_at": observed_at, "method": "crossref-doi-metadata-v1",
            "result_json": canonical(result), "claim_payload_sha256": sha256(claim[0]),
            "previous_hash": previous,
        }
        digest = sha256(canonical(event))
        db.execute("""INSERT INTO evidence_verification_events
            (claim_id, version, evidence_id, observed_at, method, result_json,
             claim_payload_sha256, previous_hash, event_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (*event.values(), digest))
        db.commit()
        return {"event_hash": digest, **event, "result": result}


def verify_doi_verification_log() -> dict:
    """Validate contiguous sequences, hash links and referenced claim payloads."""
    with connect() as db:
        _init(db)
        rows = db.execute("""SELECT seq, claim_id, version, evidence_id, observed_at, method,
            result_json, claim_payload_sha256, previous_hash, event_hash
            FROM evidence_verification_events ORDER BY seq""").fetchall()
        previous = "0" * 64
        for expected_seq, row in enumerate(rows, 1):
            seq, claim_id, version, evidence_id, observed_at, method, result_json, payload_hash, prev_hash, event_hash = row
            event = {"claim_id": claim_id, "version": version, "evidence_id": evidence_id,
                     "observed_at": observed_at, "method": method, "result_json": result_json,
                     "claim_payload_sha256": payload_hash, "previous_hash": prev_hash}
            claim = db.execute("SELECT payload FROM claims WHERE id=? AND version=?", (claim_id, version)).fetchone()
            if (seq != expected_seq or prev_hash != previous or sha256(canonical(event)) != event_hash
                    or claim is None or sha256(claim[0]) != payload_hash):
                return {"valid": False, "failed_sequence": expected_seq}
            previous = event_hash
        return {"valid": True, "events_checked": len(rows), "head_hash": previous}
