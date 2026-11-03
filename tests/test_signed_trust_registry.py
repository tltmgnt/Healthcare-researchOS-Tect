import hashlib
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.release_gates import REQUIRED_GATES
from tect.signed_release_evidence import sign_release_evidence
from tect.signed_trust_registry import (
    encode_reviewer_public_key, sign_trust_registry,
    verify_signed_trust_registry, verify_release_with_signed_registry
)

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


@pytest.fixture
def sample():
    authority = Ed25519PrivateKey.generate()
    reviewer = Ed25519PrivateKey.generate()
    entry = {"public_key_hex": encode_reviewer_public_key(reviewer.public_key()),
             "reviewer_id": "review-board", "allowed_submitters": ["operator"],
             "allowed_gates": list(REQUIRED_GATES),
             "valid_from": (NOW - timedelta(days=2)).isoformat(),
             "valid_until": (NOW + timedelta(days=2)).isoformat(), "revoked": False}
    registry = sign_trust_registry({"reviewer-key": entry}, sequence=7,
                                   authority_key_id="security-root", authority_private_key=authority)
    artifacts = {gate: gate.encode() for gate in REQUIRED_GATES}
    gates = {gate: {"passed": True, "evidence_reference": "external://" + gate,
                    "evidence_sha256": hashlib.sha256(artifacts[gate]).hexdigest(),
                    "independent_approver": "review-board",
                    "approved_at": (NOW - timedelta(days=1)).isoformat()}
             for gate in REQUIRED_GATES}
    release = sign_release_evidence(gates, submitter_id="operator",
                                    reviewer_key_id="reviewer-key", private_key=reviewer,
                                    assessed_at=NOW)
    return registry, {"security-root": authority.public_key()}, release, artifacts, authority


def test_valid_registry(sample):
    result = verify_signed_trust_registry(sample[0], sample[1], minimum_sequence=7)
    assert result["valid"] and result["sequence"] == 7


def test_valid_release_with_registry(sample):
    result = verify_release_with_signed_registry(
        sample[2], sample[3], sample[0], sample[1], minimum_sequence=7,
        expected_submitter_id="operator", assessed_at=NOW)
    assert result["authorized"] and result["release_evidence_ready"]


def test_rollback_rejected(sample):
    assert verify_signed_trust_registry(sample[0], sample[1], minimum_sequence=8)["reason"] == "registry_rollback"


def test_unknown_authority(sample):
    assert verify_signed_trust_registry(sample[0], {}, minimum_sequence=7)["reason"] == "untrusted_authority"


def test_modified_reviewer_key(sample):
    registry = deepcopy(sample[0])
    registry["entries"]["reviewer-key"]["public_key_hex"] = "0" * 64
    assert verify_signed_trust_registry(registry, sample[1], minimum_sequence=7)["reason"] == "signature_mismatch"


def test_modified_revocation(sample):
    registry = deepcopy(sample[0])
    registry["entries"]["reviewer-key"]["revoked"] = True
    assert verify_signed_trust_registry(registry, sample[1], minimum_sequence=7)["reason"] == "signature_mismatch"


def test_revoked_signed_registry_blocks_release(sample):
    registry = deepcopy(sample[0])
    registry["entries"]["reviewer-key"]["revoked"] = True
    registry = sign_trust_registry(registry["entries"], sequence=8,
                                   authority_key_id="security-root", authority_private_key=sample[4])
    result = verify_release_with_signed_registry(
        sample[2], sample[3], registry, sample[1], minimum_sequence=8,
        expected_submitter_id="operator", assessed_at=NOW)
    assert not result["authorized"] and result["reason"] == "reviewer_key_revoked"


def test_untrusted_registry_blocks_release(sample):
    result = verify_release_with_signed_registry(
        sample[2], sample[3], sample[0], {}, minimum_sequence=7,
        expected_submitter_id="operator", assessed_at=NOW)
    assert result["reason"] == "registry_verification_failed"


def test_invalid_sequence_type(sample):
    with pytest.raises(ValueError):
        verify_signed_trust_registry(sample[0], sample[1], minimum_sequence=True)


def test_extra_registry_field(sample):
    registry = dict(sample[0])
    registry["extra"] = "bad"
    assert verify_signed_trust_registry(registry, sample[1], minimum_sequence=7)["reason"] == "invalid_envelope"


def test_modified_signature(sample):
    registry = dict(sample[0])
    registry["signature_hex"] = "0" * 128
    assert verify_signed_trust_registry(registry, sample[1], minimum_sequence=7)["reason"] == "signature_mismatch"


def test_bad_reviewer_scope_signed(sample):
    entries = deepcopy(sample[0]["entries"])
    entries["reviewer-key"]["allowed_gates"] = ["engineering_ci_and_review"]
    registry = sign_trust_registry(entries, sequence=8,
                                   authority_key_id="security-root", authority_private_key=sample[4])
    assert verify_signed_trust_registry(registry, sample[1], minimum_sequence=8)["reason"] == "invalid_registry_entries"
