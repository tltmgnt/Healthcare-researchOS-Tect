import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from tect.release_gates import REQUIRED_GATES
from tect.release_evidence_integrity import verify_release_evidence

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


def inputs():
    artifacts = {gate: ("evidence:" + gate).encode() for gate in REQUIRED_GATES}
    gates = {
        gate: {"passed": True, "evidence_reference": "external://" + gate,
               "evidence_sha256": hashlib.sha256(artifacts[gate]).hexdigest(),
               "independent_approver": "review-board",
               "approved_at": (NOW - timedelta(days=1)).isoformat()}
        for gate in REQUIRED_GATES
    }
    return gates, artifacts


def run(gates=None, artifacts=None, **kwargs):
    original_gates, original_artifacts = inputs()
    return verify_release_evidence(
        original_gates if gates is None else gates,
        original_artifacts if artifacts is None else artifacts,
        submitter_id="release-operator", assessed_at=NOW, **kwargs)


def test_complete_integrity():
    result = run()
    assert result["evidence_integrity_ready"]
    assert result["verified_count"] == result["required_count"] == 9


def test_missing_artifact():
    gates, artifacts = inputs()
    del artifacts["live_provider_iam_validation"]
    assert not run(gates, artifacts)["evidence_integrity_ready"]


def test_tampered_artifact():
    gates, artifacts = inputs()
    artifacts["engineering_ci_and_review"] += b"tampered"
    assert run(gates, artifacts)["gate_results"]["engineering_ci_and_review"]["reason"] == "artifact_digest_mismatch"


def test_missing_digest():
    gates, artifacts = inputs()
    del gates["independent_security_assessment"]["evidence_sha256"]
    assert not run(gates, artifacts)["evidence_integrity_ready"]


def test_stale_approval():
    gates, artifacts = inputs()
    gates["verified_backup_and_recovery_exercise"]["approved_at"] = (NOW - timedelta(days=91)).isoformat()
    assert run(gates, artifacts)["gate_results"]["verified_backup_and_recovery_exercise"]["reason"] == "stale_approval"


def test_future_approval():
    gates, artifacts = inputs()
    gates["privacy_and_data_governance_review"]["approved_at"] = (NOW + timedelta(days=1)).isoformat()
    assert not run(gates, artifacts)["evidence_integrity_ready"]


def test_self_approval():
    gates, artifacts = inputs()
    gates["clinical_use_and_regulatory_approval"]["independent_approver"] = "release-operator"
    assert not run(gates, artifacts)["evidence_integrity_ready"]


def test_naive_approval_date():
    gates, artifacts = inputs()
    gates["engineering_ci_and_review"]["approved_at"] = "2026-11-01T00:00:00"
    assert not run(gates, artifacts)["evidence_integrity_ready"]


def test_unexpected_artifact():
    gates, artifacts = inputs()
    artifacts["unknown"] = b"unknown"
    assert not run(gates, artifacts)["evidence_integrity_ready"]


def test_missing_gate():
    gates, artifacts = inputs()
    del gates["independent_security_assessment"]
    assert not run(gates, artifacts)["evidence_integrity_ready"]


def test_oversize_artifact():
    gates, artifacts = inputs()
    artifacts["live_provider_iam_validation"] = b"x" * (2 * 1024 * 1024 + 1)
    assert not run(gates, artifacts)["evidence_integrity_ready"]


def test_invalid_max_age():
    with pytest.raises(ValueError):
        run(max_age_days=0)


def test_naive_assessment_time():
    gates, artifacts = inputs()
    with pytest.raises(ValueError):
        verify_release_evidence(gates, artifacts, submitter_id="operator",
                                assessed_at=datetime(2026, 11, 3))
