from unittest.mock import Mock, patch

from tect.approved_provider_targets import run_approved_provider_validation


def arguments():
    return dict(enabled=True, environment="non-production", approval_reference="CHG-42",
                anchor_bucket="approved", anchor_key="anchor", anchor_version_id="v1",
                anchor_sha256="a" * 64, anchor_trusted_keys={}, evidence_manifest={},
                evidence_locations={"control": {"bucket": "approved", "key": "e", "version_id": "v1"}},
                reviewer_trusted_keys={})


def run(storage=None, identity=None, **overrides):
    storage = storage or Mock()
    identity = identity or Mock()
    identity.get_caller_identity.return_value = {"Account": "123456789012"}
    args = arguments()
    args.update(overrides)
    return run_approved_provider_validation(storage, identity,
        approved_account_id="123456789012", approved_buckets={"approved"}, **args)


@patch("tect.approved_provider_targets.run_readonly_provider_validation")
def test_allowed_target_invokes_runner(runner):
    runner.return_value = {"ready": True}
    result = run()
    assert result["ready"]
    assert result["target_approval"]["identity_checked"]
    runner.assert_called_once()


@patch("tect.approved_provider_targets.run_readonly_provider_validation")
def test_disabled_never_calls_identity_or_runner(runner):
    identity = Mock()
    result = run(identity=identity, enabled=False)
    assert result["reason"] == "explicit_opt_in_required"
    identity.get_caller_identity.assert_not_called()
    runner.assert_not_called()


@patch("tect.approved_provider_targets.run_readonly_provider_validation")
def test_production_blocked(runner):
    assert run(environment="production")["reason"] == "non_production_only"
    runner.assert_not_called()


@patch("tect.approved_provider_targets.run_readonly_provider_validation")
def test_unapproved_anchor_blocked(runner):
    assert run(anchor_bucket="production")["reason"] == "unapproved_anchor_bucket"
    runner.assert_not_called()


@patch("tect.approved_provider_targets.run_readonly_provider_validation")
def test_unapproved_evidence_blocked(runner):
    locations = {"control": {"bucket": "production", "key": "e", "version_id": "v1"}}
    assert run(evidence_locations=locations)["reason"] == "unapproved_evidence_bucket"
    runner.assert_not_called()


@patch("tect.approved_provider_targets.run_readonly_provider_validation")
def test_identity_mismatch_blocked(runner):
    identity = Mock()
    identity.get_caller_identity.return_value = {"Account": "999999999999"}
    assert run(identity=identity)["reason"] == "account_mismatch"
    runner.assert_not_called()


@patch("tect.approved_provider_targets.run_readonly_provider_validation")
def test_identity_failure_blocked(runner):
    identity = Mock()
    identity.get_caller_identity.side_effect = RuntimeError("offline")
    assert run(identity=identity)["reason"] == "identity_lookup_failed"
    runner.assert_not_called()


@patch("tect.approved_provider_targets.run_readonly_provider_validation")
def test_missing_approval_blocked(runner):
    assert run(approval_reference="")["reason"] == "approval_reference_required"
    runner.assert_not_called()


@patch("tect.approved_provider_targets.run_readonly_provider_validation")
def test_invalid_location_blocked(runner):
    assert run(evidence_locations={"control": None})["reason"] == "unapproved_evidence_bucket"
    runner.assert_not_called()
