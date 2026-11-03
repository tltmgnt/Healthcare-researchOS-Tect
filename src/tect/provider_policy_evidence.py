"""Signed reviewer assessment binding to provider IAM-policy evidence bytes.

A valid signature proves byte integrity and reviewer-key possession, not
that the provider issued the report or the permissions are effective.
"""
import hashlib
import re
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .storage import canonical

SCHEMA = "tect.provider-policy-assessment.ed25519.v1"
MAX_REPORT_BYTES = 2 * 1024 * 1024
_HEX = re.compile(r"^[0-9a-f]{128}$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
REQUIRED_ASSERTIONS = frozenset({
    "effective_read_permissions_confirmed",
    "effective_mutating_permissions_denied",
    "approved_resource_scope_confirmed",
    "independent_reviewer_confirmed",
})


def _validate_report(report: bytes) -> None:
    if not isinstance(report, bytes) or not report or len(report) > MAX_REPORT_BYTES:
        raise ValueError("Nonempty provider report bytes required within size limit")


def sign_policy_assessment(report: bytes, *, account_id: str, approval_reference: str,
                           reviewer_key_id: str, assertions: dict,
                           private_key: Ed25519PrivateKey,
                           assessed_at: datetime | None = None) -> dict:
    """Sign a complete independent assessment and its exact evidence digest."""
    _validate_report(report)
    if not isinstance(account_id, str) or not _ACCOUNT.fullmatch(account_id):
        raise ValueError("Valid provider account ID required")
    if not isinstance(approval_reference, str) or not approval_reference.strip():
        raise ValueError("Approval reference required")
    if not isinstance(reviewer_key_id, str) or not reviewer_key_id.strip():
        raise ValueError("Reviewer key ID required")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Ed25519 private key required")
    if not isinstance(assertions, dict) or set(assertions) != REQUIRED_ASSERTIONS or any(value is not True for value in assertions.values()):
        raise ValueError("All policy assertions must explicitly pass")
    now = assessed_at if assessed_at is not None else datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Timezone-aware assessment date required")
    payload = {"schema": SCHEMA, "account_id": account_id,
               "approval_reference": approval_reference, "reviewer_key_id": reviewer_key_id,
               "assessed_at": now.isoformat(), "assertions": assertions,
               "report_sha256": hashlib.sha256(report).hexdigest(),
               "report_size_bytes": len(report)}
    return {**payload, "signature_hex": private_key.sign(canonical(payload).encode("utf-8")).hex()}


def verify_policy_assessment(envelope: dict, report: bytes,
                             trusted_public_keys: dict[str, Ed25519PublicKey], *,
                             expected_account_id: str, expected_approval_reference: str) -> dict:
    """Fail closed on untrusted reviewer, scope mismatch, or altered report."""
    fields = {"schema", "account_id", "approval_reference", "reviewer_key_id",
              "assessed_at", "assertions", "report_sha256", "report_size_bytes", "signature_hex"}
    if not isinstance(envelope, dict) or set(envelope) != fields or envelope.get("schema") != SCHEMA:
        return {"valid": False, "reason": "invalid_envelope"}
    if (envelope["account_id"] != expected_account_id
            or envelope["approval_reference"] != expected_approval_reference):
        return {"valid": False, "reason": "scope_mismatch"}
    if (not isinstance(envelope["account_id"], str) or not _ACCOUNT.fullmatch(envelope["account_id"])
            or not isinstance(envelope["approval_reference"], str) or not envelope["approval_reference"].strip()
            or not isinstance(envelope["reviewer_key_id"], str) or not envelope["reviewer_key_id"].strip()
            or not isinstance(envelope["assessed_at"], str)):
        return {"valid": False, "reason": "invalid_envelope"}
    try:
        parsed = datetime.fromisoformat(envelope["assessed_at"])
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return {"valid": False, "reason": "invalid_envelope"}
    except ValueError:
        return {"valid": False, "reason": "invalid_envelope"}
    if (not isinstance(envelope["assertions"], dict)
            or set(envelope["assertions"]) != REQUIRED_ASSERTIONS
            or any(value is not True for value in envelope["assertions"].values())
            or not isinstance(envelope["report_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", envelope["report_sha256"])
            or type(envelope["report_size_bytes"]) is not int
            or not 0 < envelope["report_size_bytes"] <= MAX_REPORT_BYTES):
        return {"valid": False, "reason": "invalid_envelope"}
    signature = envelope["signature_hex"]
    if not isinstance(signature, str) or not _HEX.fullmatch(signature):
        return {"valid": False, "reason": "invalid_signature"}
    key = trusted_public_keys.get(envelope["reviewer_key_id"]) if isinstance(trusted_public_keys, dict) else None
    if not isinstance(key, Ed25519PublicKey):
        return {"valid": False, "reason": "untrusted_reviewer"}
    payload = {k: envelope[k] for k in fields - {"signature_hex"}}
    try:
        key.verify(bytes.fromhex(signature), canonical(payload).encode("utf-8"))
    except (InvalidSignature, ValueError, TypeError):
        return {"valid": False, "reason": "signature_mismatch"}
    if (not isinstance(report, bytes) or len(report) != envelope["report_size_bytes"]
            or hashlib.sha256(report).hexdigest() != envelope["report_sha256"]):
        return {"valid": False, "reason": "report_digest_mismatch"}
    return {"valid": True, "account_id": expected_account_id,
            "approval_reference": expected_approval_reference,
            "reviewer_key_id": envelope["reviewer_key_id"],
            "limitations": "Reviewer-signed report integrity only; provider provenance and effective permissions unverified"}
