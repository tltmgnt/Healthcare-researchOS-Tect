from datetime import datetime, timezone

import pytest

from tect.release_gates import REQUIRED_GATES, evaluate_release_gates

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def complete():
    return {name: {"passed": True, "evidence_reference": "external://approval/" + name,
                   "independent_approver": "review-board",
                   "approved_at": "2026-01-01T00:00:00Z"}
            for name in REQUIRED_GATES}


def test_complete_attestations():
    result = evaluate_release_gates(complete(), assessed_at=NOW)
    assert result["release_gates_attested"]
    assert result["passed_count"] == result["required_count"] == 9


def test_empty_fails():
    assert not evaluate_release_gates({}, assessed_at=NOW)["release_gates_attested"]


def test_missing_security_review_fails():
    gates = complete()
    del gates["independent_security_assessment"]
    assert not evaluate_release_gates(gates, assessed_at=NOW)["release_gates_attested"]


def test_failed_clinical_approval_fails():
    gates = complete()
    gates["clinical_use_and_regulatory_approval"]["passed"] = False
    assert not evaluate_release_gates(gates, assessed_at=NOW)["release_gates_attested"]


def test_missing_evidence_fails():
    gates = complete()
    gates["live_object_lock_deletion_denial"]["evidence_reference"] = ""
    assert not evaluate_release_gates(gates, assessed_at=NOW)["release_gates_attested"]


def test_missing_approver_fails():
    gates = complete()
    gates["independent_storage_and_key_custody"]["independent_approver"] = ""
    assert not evaluate_release_gates(gates, assessed_at=NOW)["release_gates_attested"]


def test_unexpected_gate_fails():
    gates = complete()
    gates["override"] = {"passed": True}
    result = evaluate_release_gates(gates, assessed_at=NOW)
    assert not result["release_gates_attested"]
    assert result["unexpected_gates"] == ["override"]


def test_truthy_non_boolean_fails():
    gates = complete()
    gates["engineering_ci_and_review"]["passed"] = 1
    assert not evaluate_release_gates(gates, assessed_at=NOW)["release_gates_attested"]


def test_naive_time_rejected():
    with pytest.raises(ValueError):
        evaluate_release_gates(complete(), assessed_at=datetime(2026, 1, 1))


def test_non_dict_rejected():
    with pytest.raises(ValueError):
        evaluate_release_gates([], assessed_at=NOW)
