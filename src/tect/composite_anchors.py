"""Ed25519 signed composite anchors for claim and DOI verification histories.

Composite anchors are new artifacts; legacy signed checkpoints remain unchanged.
"""
import hmac
from contextlib import nullcontext
import re
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .storage import canonical, verify_audit_chain
from .verification_records import verify_doi_verification_log, _init
from .storage import connect, sha256

SCHEMA = "tect.composite-audit-anchor.ed25519.v1"
_HEX = re.compile(r"^[0-9a-f]{64}$")


def sign_composite_anchor(private_key: Ed25519PrivateKey, key_id: str) -> dict:
    if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("Ed25519 private key and nonempty key_id required")
    # One SQLite read transaction pins both heads to the same database snapshot.
    with connect() as db:
        db.execute("BEGIN")
        claims = verify_audit_chain(db)
        evidence = verify_doi_verification_log(db)
        db.rollback()
    if not claims["valid"] or not evidence["valid"]:
        raise ValueError("Audit verification failed; refusing to sign")
    envelope = {
        "schema": SCHEMA, "key_id": key_id,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "claims": {"events_checked": claims["events_checked"], "head_hash": claims["head_hash"]},
        "doi_verifications": {"events_checked": evidence["events_checked"], "head_hash": evidence["head_hash"]},
    }
    envelope["signature_hex"] = private_key.sign(canonical(envelope).encode("utf-8")).hex()
    return envelope


def _verification_prefix(count: int, head: str, db=None) -> dict:
    """Validate the complete local verification history, then match its prefix."""
    with (connect() if db is None else nullcontext(db)) as db:
        _init(db)
        rows = db.execute("""SELECT seq, claim_id, version, evidence_id, observed_at, method,
            result_json, claim_payload_sha256, previous_hash, event_hash
            FROM evidence_verification_events ORDER BY seq""").fetchall()
        previous = "0" * 64
        prefix = previous if count == 0 else None
        for index, row in enumerate(rows, 1):
            seq, claim_id, version, evidence_id, observed_at, method, result_json, payload_hash, prev_hash, event_hash = row
            event = {"claim_id": claim_id, "version": version, "evidence_id": evidence_id,
                     "observed_at": observed_at, "method": method, "result_json": result_json,
                     "claim_payload_sha256": payload_hash, "previous_hash": prev_hash}
            claim = db.execute("SELECT payload FROM claims WHERE id=? AND version=?", (claim_id, version)).fetchone()
            if (seq != index or prev_hash != previous or sha256(canonical(event)) != event_hash
                    or claim is None or sha256(claim[0]) != payload_hash):
                return {"valid": False, "reason": "doi_log_invalid"}
            previous = event_hash
            if index == count:
                prefix = previous
        if prefix is None or not hmac.compare_digest(prefix, head):
            return {"valid": False, "reason": "doi_prefix_mismatch"}
        return {"valid": True, "events_checked": count, "current_events": len(rows)}


def verify_composite_anchor(envelope: dict, trusted_public_keys: dict[str, Ed25519PublicKey]) -> dict:
    required = {"schema", "key_id", "captured_at", "claims", "doi_verifications", "signature_hex"}
    if not isinstance(envelope, dict) or set(envelope) != required or envelope.get("schema") != SCHEMA:
        return {"valid": False, "reason": "invalid_envelope"}
    key_id = envelope["key_id"]
    if not isinstance(key_id, str) or not key_id.strip() or not isinstance(envelope["captured_at"], str):
        return {"valid": False, "reason": "invalid_envelope"}
    for name in ("claims", "doi_verifications"):
        part = envelope[name]
        if (not isinstance(part, dict) or set(part) != {"events_checked", "head_hash"}
                or type(part["events_checked"]) is not int or part["events_checked"] < 0
                or not isinstance(part["head_hash"], str) or not _HEX.fullmatch(part["head_hash"])):
            return {"valid": False, "reason": "invalid_envelope"}
    signature = envelope["signature_hex"]
    if not isinstance(signature, str) or len(signature) != 128:
        return {"valid": False, "reason": "invalid_signature"}
    key = trusted_public_keys.get(key_id)
    if not isinstance(key, Ed25519PublicKey):
        return {"valid": False, "reason": "untrusted_key"}
    try:
        key.verify(bytes.fromhex(signature), canonical({k: envelope[k] for k in required - {"signature_hex"}}).encode("utf-8"))
    except (InvalidSignature, ValueError, TypeError):
        return {"valid": False, "reason": "signature_mismatch"}
    from .historical_audit import verify_audit_prefix
    claims = envelope["claims"]
    # Pin both historical prefix checks to one SQLite read snapshot.
    with connect() as db:
        db.execute("BEGIN")
        result = verify_audit_prefix(claims["events_checked"], claims["head_hash"], db=db)
        if not result["valid"]:
            db.rollback()
            return {"valid": False, "reason": "claims_prefix_invalid", "detail": result}
        doi = envelope["doi_verifications"]
        verification = _verification_prefix(doi["events_checked"], doi["head_hash"], db=db)
        db.rollback()
        return verification
