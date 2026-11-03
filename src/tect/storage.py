"""SQLite-backed versioned claims and tamper-evident event chain.

Hash chaining detects changes relative to a trusted anchor; it does not prevent
a database administrator from rewriting the entire chain.
"""
import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone

from .models import Claim


def database_path() -> str:
    return os.environ.get("TECT_DB_PATH", "tect.sqlite3")


@contextmanager
def connect():
    db = sqlite3.connect(database_path(), timeout=10)
    try:
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("CREATE TABLE IF NOT EXISTS claims (id TEXT NOT NULL, version INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(id, version))")
        db.execute("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, claim_id TEXT NOT NULL, version INTEGER NOT NULL, timestamp TEXT NOT NULL, payload_sha256 TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)")
        db.commit()
        yield db
    finally:
        db.close()


def canonical(data: object) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def save_claim(claim: Claim, *, expected_version: int | None = None) -> int:
    payload = canonical(claim.model_dump(mode="json"))
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT MAX(version) FROM claims WHERE id=?", (claim.id,)).fetchone()
        current = row[0] or 0
        if expected_version is not None and current != expected_version:
            raise ValueError("Version conflict")
        version = current + 1
        db.execute("INSERT INTO claims VALUES (?, ?, ?)", (claim.id, version, payload))
        from .provenance import _snapshot
        db.execute("CREATE TABLE IF NOT EXISTS evidence_provenance (claim_id TEXT NOT NULL, version INTEGER NOT NULL, manifest TEXT NOT NULL, manifest_sha256 TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(claim_id, version))")
        manifest = canonical(_snapshot(claim.id, version, payload))
        db.execute("INSERT INTO evidence_provenance VALUES (?, ?, ?, ?, ?)",
                   (claim.id, version, manifest, sha256(manifest), datetime.now(timezone.utc).isoformat()))
        previous = db.execute("SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = previous[0] if previous else "0" * 64
        timestamp = datetime.now(timezone.utc).isoformat()
        event = dict(event_type="claim.saved.provenance", claim_id=claim.id, version=version,
                     timestamp=timestamp, payload_sha256=sha256(payload), previous_hash=prev_hash)
        event_hash = sha256(canonical(event))
        db.execute(
            "INSERT INTO events (event_type, claim_id, version, timestamp, payload_sha256, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event["event_type"], claim.id, version, timestamp, event["payload_sha256"], prev_hash, event_hash),
        )
        db.commit()
        return version


def load_claim(claim_id: str, version: int | None = None) -> Claim | None:
    with connect() as db:
        if version is None:
            row = db.execute("SELECT payload FROM claims WHERE id=? ORDER BY version DESC LIMIT 1", (claim_id,)).fetchone()
        else:
            row = db.execute("SELECT payload FROM claims WHERE id=? AND version=?", (claim_id, version)).fetchone()
    return Claim.model_validate_json(row[0]) if row else None


def claim_versions(claim_id: str) -> list[int]:
    with connect() as db:
        return [row[0] for row in db.execute("SELECT version FROM claims WHERE id=? ORDER BY version", (claim_id,))]


def verify_audit_chain(db=None) -> dict:
    with (connect() if db is None else nullcontext(db)) as db:
        rows = db.execute("SELECT seq, event_type, claim_id, version, timestamp, payload_sha256, previous_hash, event_hash FROM events ORDER BY seq").fetchall()
        previous = "0" * 64
        for index, (seq, kind, claim_id, version, timestamp, payload_hash, prev_hash, event_hash) in enumerate(rows, 1):
            event = dict(event_type=kind, claim_id=claim_id, version=version, timestamp=timestamp,
                         payload_sha256=payload_hash, previous_hash=prev_hash)
            payload_row = db.execute("SELECT payload FROM claims WHERE id=? AND version=?", (claim_id, version)).fetchone()
            provenance_valid = True
            if kind == "claim.saved.provenance" and payload_row is not None:
                from .provenance import _snapshot
                manifest_row = db.execute(
                    "SELECT manifest, manifest_sha256 FROM evidence_provenance WHERE claim_id=? AND version=?",
                    (claim_id, version),
                ).fetchone()
                expected_manifest = canonical(_snapshot(claim_id, version, payload_row[0]))
                provenance_valid = (manifest_row is not None
                                    and manifest_row[0] == expected_manifest
                                    and manifest_row[1] == sha256(expected_manifest))
            if (seq != index or not provenance_valid
                    or prev_hash != previous or sha256(canonical(event)) != event_hash
                    or payload_row is None or sha256(payload_row[0]) != payload_hash):
                return {"valid": False, "events_checked": index - 1, "failed_sequence": index}
            previous = event_hash
        return {"valid": True, "events_checked": len(rows), "head_hash": previous}
