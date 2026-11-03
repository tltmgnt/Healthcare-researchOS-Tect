from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from tect.provider_integration_readiness import run_readonly_provider_validation

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def args():
    return dict(enabled=True, environment="non-production", approval_reference="ticket-123",
                anchor_bucket="test-bucket", anchor_key="anchor.json",
                anchor_version_id="version-1", anchor_sha256="a" * 64,
                anchor_trusted_keys={}, evidence_manifest={"schema": "test"},
                evidence_locations={"a": {"bucket": "test", "key": "one", "version_id": "v1"}},
                reviewer_trusted_keys={}, checked_at=NOW)


def test_opt_in_required_before_provider_calls():
    client = Mock()
    result = run_readonly_provider_validation(client, **{**args(), "enabled": False})
    assert result["reason"] == "explicit_opt_in_required"
    client.assert_not_called()


def test_production_blocked():
    client = Mock()
    result = run_readonly_provider_validation(client, **{**args(), "environment": "production"})
    assert result["reason"] == "non_production_only"
    client.assert_not_called()


def test_approval_required():
    result = run_readonly_provider_validation(Mock(), **{**args(), "approval_reference": ""})
    assert result["reason"] == "approval_reference_required"


def test_pinned_anchor_required():
    result = run_readonly_provider_validation(Mock(), **{**args(), "anchor_version_id": ""})
    assert result["reason"] == "pinned_anchor_required"


def test_pinned_evidence_required():
    result = run_readonly_provider_validation(Mock(), **{**args(), "evidence_locations": {}})
    assert result["reason"] == "pinned_evidence_required"


@patch("tect.provider_integration_readiness.verify_retrieved_evidence")
@patch("tect.provider_integration_readiness.audit_composite_anchor_recovery")
def test_all_checks_green(anchor, evidence):
    anchor.return_value = {"ready": True}
    evidence.return_value = {"valid": True}
    result = run_readonly_provider_validation(Mock(), **args())
    assert result["ready"]
    assert result["checks"] == {"anchor_recovery": True, "evidence_integrity": True}
    assert result["approval_reference"] == "ticket-123"


@patch("tect.provider_integration_readiness.verify_retrieved_evidence")
@patch("tect.provider_integration_readiness.audit_composite_anchor_recovery")
def test_anchor_failure_fails_closed(anchor, evidence):
    anchor.return_value = {"ready": False}
    evidence.return_value = {"valid": True}
    assert not run_readonly_provider_validation(Mock(), **args())["ready"]


@patch("tect.provider_integration_readiness.verify_retrieved_evidence")
@patch("tect.provider_integration_readiness.audit_composite_anchor_recovery")
def test_evidence_failure_fails_closed(anchor, evidence):
    anchor.return_value = {"ready": True}
    evidence.return_value = {"valid": False}
    assert not run_readonly_provider_validation(Mock(), **args())["ready"]


@patch("tect.provider_integration_readiness.verify_retrieved_evidence")
@patch("tect.provider_integration_readiness.audit_composite_anchor_recovery")
def test_provider_exceptions_fail_closed(anchor, evidence):
    anchor.side_effect = RuntimeError("unavailable")
    evidence.side_effect = RuntimeError("unavailable")
    result = run_readonly_provider_validation(Mock(), **args())
    assert not result["ready"]
    assert result["details"]["anchor"]["reason"] == "anchor_audit_failed"


def test_naive_time_rejected():
    with pytest.raises(ValueError):
        run_readonly_provider_validation(Mock(), **{**args(), "checked_at": datetime(2026, 1, 1)})
