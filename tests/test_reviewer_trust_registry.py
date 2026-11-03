import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.release_gates import REQUIRED_GATES
from tect.reviewer_trust_registry import verify_with_reviewer_registry
from tect.signed_release_evidence import sign_release_evidence

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


@pytest.fixture
def sample():
    key = Ed25519PrivateKey.generate()
    artifacts = {gate: gate.encode() for gate in REQUIRED_GATES}
    gates = {gate: {"passed": True, "evidence_reference": "external://" + gate,
                    "evidence_sha256": hashlib.sha256(artifacts[gate]).hexdigest(),
                    "independent_approver": "reviewer", "approved_at": (NOW - timedelta(days=1)).isoformat()}
             for gate in REQUIRED_GATES}
    envelope = sign_release_evidence(gates, submitter_id="operator",
                                     reviewer_key_id="key-1", private_key=key, assessed_at=NOW)
    registry = {"key-1": {"public_key": key.public_key(), "reviewer_id": "reviewer",
                          "allowed_submitters": {"operator"},
                          "allowed_gates": set(REQUIRED_GATES),
                          "valid_from": NOW - timedelta(days=2),
                          "valid_until": NOW + timedelta(days=2), "revoked": False}}
    return envelope, artifacts, registry


def run(sample):
    return verify_with_reviewer_registry(*sample, expected_submitter_id="operator", assessed_at=NOW)


def test_authorized(sample):
    result = run(sample)
    assert result["authorized"] and result["release_evidence_ready"]


def test_revoked(sample):
    sample[2]["key-1"]["revoked"] = True
    assert run(sample)["reason"] == "reviewer_key_revoked"


def test_expired(sample):
    sample[2]["key-1"]["valid_until"] = NOW - timedelta(days=1)
    assert run(sample)["reason"] == "reviewer_key_outside_validity"


def test_not_yet_valid(sample):
    sample[2]["key-1"]["valid_from"] = NOW + timedelta(days=1)
    assert run(sample)["reason"] == "reviewer_key_outside_validity"


def test_unknown_reviewer(sample):
    sample[2].clear()
    assert run(sample)["reason"] == "reviewer_not_registered"


def test_unapproved_submitter(sample):
    sample[2]["key-1"]["allowed_submitters"] = {"other"}
    assert run(sample)["reason"] == "submitter_not_authorized"


def test_insufficient_gate_scope(sample):
    sample[2]["key-1"]["allowed_gates"] = {"engineering_ci_and_review"}
    assert run(sample)["reason"] == "gate_scope_not_authorized"


def test_reviewer_submitter_conflict(sample):
    sample[2]["key-1"]["reviewer_id"] = "operator"
    assert run(sample)["reason"] == "reviewer_submitter_conflict"


def test_naive_key_date(sample):
    sample[2]["key-1"]["valid_from"] = datetime(2026, 11, 1)
    assert run(sample)["reason"] == "reviewer_key_outside_validity"


def test_tampered_artifact(sample):
    sample[1]["engineering_ci_and_review"] = b"tampered"
    result = run(sample)
    assert result["authorized"] and not result["release_evidence_ready"]


def test_bad_registry_shape(sample):
    del sample[2]["key-1"]["revoked"]
    assert run(sample)["reason"] == "reviewer_not_registered"


def test_invalid_public_key(sample):
    sample[2]["key-1"]["public_key"] = "not-a-key"
    assert run(sample)["reason"] == "invalid_reviewer_public_key"
