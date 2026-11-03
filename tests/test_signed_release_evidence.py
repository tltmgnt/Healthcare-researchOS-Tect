import hashlib
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.release_gates import REQUIRED_GATES
from tect.signed_release_evidence import sign_release_evidence, verify_signed_release_evidence

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


@pytest.fixture
def sample():
    key = Ed25519PrivateKey.generate()
    artifacts = {name: ("report:" + name).encode() for name in REQUIRED_GATES}
    gates = {
        name: {"passed": True, "evidence_reference": "external://" + name,
               "evidence_sha256": hashlib.sha256(artifacts[name]).hexdigest(),
               "independent_approver": "independent-reviewer",
               "approved_at": (NOW - timedelta(days=1)).isoformat()}
        for name in REQUIRED_GATES
    }
    envelope = sign_release_evidence(
        gates, submitter_id="operator", reviewer_key_id="reviewer-key",
        private_key=key, assessed_at=NOW)
    return envelope, artifacts, key


def verify(sample, *, envelope=None, artifacts=None, keys=None, submitter="operator", now=NOW):
    original, files, key = sample
    return verify_signed_release_evidence(
        original if envelope is None else envelope,
        files if artifacts is None else artifacts,
        {"reviewer-key": key.public_key()} if keys is None else keys,
        expected_submitter_id=submitter, assessed_at=now)


def test_valid(sample):
    result = verify(sample)
    assert result["valid"] and result["release_evidence_ready"]


def test_modified_artifact(sample):
    artifacts = dict(sample[1])
    artifacts["engineering_ci_and_review"] += b"!"
    result = verify(sample, artifacts=artifacts)
    assert result["valid"] and not result["release_evidence_ready"]


def test_modified_gate(sample):
    envelope = deepcopy(sample[0])
    envelope["gates"]["engineering_ci_and_review"]["passed"] = False
    assert verify(sample, envelope=envelope)["reason"] == "signature_mismatch"


def test_modified_signature(sample):
    envelope = deepcopy(sample[0])
    envelope["signature_hex"] = "0" * 128
    assert verify(sample, envelope=envelope)["reason"] == "signature_mismatch"


def test_untrusted_key(sample):
    assert verify(sample, keys={})["reason"] == "untrusted_reviewer"


def test_wrong_submitter(sample):
    assert verify(sample, submitter="different")["reason"] == "submitter_mismatch"


def test_future_assessment(sample):
    assert verify(sample, now=NOW - timedelta(minutes=1))["reason"] == "future_assessment"


def test_stale_assessment(sample):
    assert verify(sample, now=NOW + timedelta(days=2))["reason"] == "stale_assessment"


def test_naive_signing_date(sample):
    with pytest.raises(ValueError):
        sign_release_evidence(sample[0]["gates"], submitter_id="operator",
                              reviewer_key_id="reviewer-key", private_key=sample[2],
                              assessed_at=datetime(2026, 11, 3))


def test_bad_reviewer_id(sample):
    with pytest.raises(ValueError):
        sign_release_evidence(sample[0]["gates"], submitter_id="operator",
                              reviewer_key_id="", private_key=sample[2],
                              assessed_at=NOW)


def test_extra_envelope_field(sample):
    envelope = dict(sample[0])
    envelope["extra"] = "not allowed"
    assert verify(sample, envelope=envelope)["reason"] == "invalid_envelope"


def test_missing_artifact(sample):
    artifacts = dict(sample[1])
    del artifacts["live_provider_iam_validation"]
    assert not verify(sample, artifacts=artifacts)["release_evidence_ready"]
