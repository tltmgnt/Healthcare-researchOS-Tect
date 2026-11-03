from datetime import datetime, timezone
import pytest
from tect.provider_validation import REQUIRED_CONTROLS, evaluate_provider_validation

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def evidence():
    return {name: {"passed": True, "evidence_reference": "external://audit/" + name,
                   "reviewer": "independent-auditor", "reviewed_at": "2026-01-01T00:00:00Z"}
            for name in REQUIRED_CONTROLS}


def test_all_attested():
    result = evaluate_provider_validation(evidence(), checked_at=NOW)
    assert result["ready"]
    assert result["accepted_count"] == result["required_count"] == 6


def test_empty_fails():
    assert not evaluate_provider_validation({}, checked_at=NOW)["ready"]


def test_missing_control_fails():
    records = evidence()
    del records["denied_deletion_test"]
    assert not evaluate_provider_validation(records, checked_at=NOW)["ready"]


def test_failed_control_fails():
    records = evidence()
    records["anchor_retrieval_and_recovery"]["passed"] = False
    assert not evaluate_provider_validation(records, checked_at=NOW)["ready"]


def test_missing_reference_fails():
    records = evidence()
    records["object_lock_compliance_retention"]["evidence_reference"] = ""
    assert not evaluate_provider_validation(records, checked_at=NOW)["ready"]


def test_missing_reviewer_fails():
    records = evidence()
    records["independent_signing_key_custody"]["reviewer"] = ""
    assert not evaluate_provider_validation(records, checked_at=NOW)["ready"]


def test_boolean_strictness():
    records = evidence()
    records["credential_rotation_and_revocation"]["passed"] = 1
    assert not evaluate_provider_validation(records, checked_at=NOW)["ready"]


def test_naive_datetime_rejected():
    with pytest.raises(ValueError):
        evaluate_provider_validation(evidence(), checked_at=datetime(2026, 1, 1))
