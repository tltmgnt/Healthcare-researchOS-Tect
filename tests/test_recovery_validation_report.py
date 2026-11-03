from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.provider_policy_evidence import REQUIRED_ASSERTIONS, sign_policy_assessment
from tect.recovery_validation_report import generate_recovery_validation_report

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
REPORT = b"synthetic IAM policy assessment"


@pytest.fixture
def args():
    key = Ed25519PrivateKey.generate()
    policy = sign_policy_assessment(
        REPORT, account_id="123456789012", approval_reference="CHG-42",
        reviewer_key_id="reviewer", assertions={name: True for name in REQUIRED_ASSERTIONS},
        private_key=key, assessed_at=NOW
    )
    return dict(policy_envelope=policy, policy_report=REPORT,
                trusted_reviewer_keys={"reviewer": key.public_key()},
                approved_account_id="123456789012", approved_buckets={"test"},
                enabled=True, environment="non-production", approval_reference="CHG-42",
                anchor_bucket="test", anchor_key="anchor", anchor_version_id="v1",
                anchor_sha256="a" * 64, anchor_trusted_keys={},
                evidence_manifest={}, evidence_locations={"x": {"bucket": "test"}},
                reviewer_trusted_keys={}, checked_at=NOW)


def run(args):
    return generate_recovery_validation_report(Mock(), Mock(), **args)


@patch("tect.recovery_validation_report.run_approved_provider_validation")
def test_combined_success(provider, args):
    provider.return_value = {"ready": True}
    result = run(args)
    assert result["ready"]
    assert all(result["checks"].values())
    provider.assert_called_once()


@patch("tect.recovery_validation_report.run_approved_provider_validation")
def test_provider_failure_fails_closed(provider, args):
    provider.return_value = {"ready": False, "reason": "account_mismatch"}
    assert not run(args)["ready"]


@patch("tect.recovery_validation_report.run_approved_provider_validation")
def test_tampered_policy_blocks_provider(provider, args):
    args["policy_report"] += b"!"
    assert run(args)["reason"] == "policy_assessment_invalid"
    provider.assert_not_called()


@patch("tect.recovery_validation_report.run_approved_provider_validation")
def test_untrusted_reviewer_blocks_provider(provider, args):
    args["trusted_reviewer_keys"] = {}
    assert run(args)["reason"] == "policy_assessment_invalid"
    provider.assert_not_called()


@patch("tect.recovery_validation_report.run_approved_provider_validation")
def test_wrong_account_blocks_provider(provider, args):
    args["approved_account_id"] = "999999999999"
    assert run(args)["reason"] == "policy_assessment_invalid"
    provider.assert_not_called()


@patch("tect.recovery_validation_report.run_approved_provider_validation")
def test_wrong_approval_blocks_provider(provider, args):
    args["approval_reference"] = "CHG-99"
    assert run(args)["reason"] == "policy_assessment_invalid"
    provider.assert_not_called()


@patch("tect.recovery_validation_report.run_approved_provider_validation")
def test_disabled_blocks_provider(provider, args):
    args["enabled"] = False
    assert run(args)["reason"] == "explicit_opt_in_required"
    provider.assert_not_called()


@patch("tect.recovery_validation_report.run_approved_provider_validation")
def test_production_blocks_provider(provider, args):
    args["environment"] = "production"
    assert run(args)["reason"] == "non_production_only"
    provider.assert_not_called()


def test_naive_datetime_rejected(args):
    args["checked_at"] = datetime(2026, 1, 1)
    with pytest.raises(ValueError):
        run(args)
