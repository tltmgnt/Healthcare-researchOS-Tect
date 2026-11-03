import io
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.durable_registry_floor import RegistryFloorStore
from tect.external_floor_anchors import sign_floor_anchor
from tect.floor_anchor_retention_assurance import verify_retained_floor_anchor

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)
ACCOUNT = "123456789012"


@pytest.fixture
def sample(tmp_path):
    store = RegistryFloorStore.provision(str(tmp_path / "floor.db"), initial_sequence=7)
    signer = Ed25519PrivateKey.generate()
    anchor = sign_floor_anchor(store, authority_key_id="root", private_key=signer, created_at=NOW)
    storage, identity = Mock(), Mock()
    identity.get_caller_identity.return_value = {"Account": ACCOUNT}
    storage.get_object.return_value = {"VersionId": "v1", "Body": io.BytesIO(json.dumps(anchor).encode())}
    storage.get_object_retention.return_value = {"Retention": {
        "Mode": "COMPLIANCE", "RetainUntilDate": NOW + timedelta(days=100)}}
    storage.get_object_legal_hold.return_value = {"LegalHold": {"Status": "ON"}}
    return store, storage, identity, signer


def run(sample, **overrides):
    store, storage, identity, signer = sample
    storage.get_object.return_value["Body"] = io.BytesIO(json.dumps(
        sign_floor_anchor(store, authority_key_id="root", private_key=signer, created_at=NOW)).encode())
    args = dict(bucket="approved-bucket", key="floor.json", version_id="v1",
                approved_account_id=ACCOUNT, approved_buckets={"approved-bucket"},
                trusted_authorities={"root": signer.public_key()},
                independently_pinned_sequence=7, checked_at=NOW,
                approval_reference="CAB-123", enabled=True, environment="non-production",
                local_store=store)
    args.update(overrides)
    return verify_retained_floor_anchor(storage, identity, **args)


def test_valid_retained_anchor(sample):
    assert run(sample)["ready"]


def test_no_opt_in_blocks_calls(sample):
    assert run(sample, enabled=False)["reason"] == "anchor_verification_failed"
    sample[2].get_caller_identity.assert_not_called()
    sample[1].get_object_retention.assert_not_called()


def test_production_denied(sample):
    assert not run(sample, environment="production")["ready"]
    sample[1].get_object_retention.assert_not_called()


def test_unapproved_bucket_denied(sample):
    assert not run(sample, bucket="wrong")["ready"]
    sample[1].get_object_retention.assert_not_called()


def test_wrong_account_denied(sample):
    sample[2].get_caller_identity.return_value = {"Account": "000000000000"}
    assert not run(sample)["ready"]
    sample[1].get_object_retention.assert_not_called()


def test_governance_mode_denied(sample):
    sample[1].get_object_retention.return_value["Retention"]["Mode"] = "GOVERNANCE"
    assert run(sample)["reason"] == "compliance_mode_required"


def test_expired_retention_denied(sample):
    sample[1].get_object_retention.return_value["Retention"]["RetainUntilDate"] = NOW - timedelta(days=1)
    assert run(sample)["reason"] == "retention_expired"


def test_insufficient_retention_denied(sample):
    sample[1].get_object_retention.return_value["Retention"]["RetainUntilDate"] = NOW + timedelta(days=10)
    assert run(sample)["reason"] == "retention_below_threshold"


def test_hold_off_denied(sample):
    sample[1].get_object_legal_hold.return_value["LegalHold"]["Status"] = "OFF"
    assert run(sample)["reason"] == "legal_hold_required"


def test_version_mismatch_denied(sample):
    sample[1].get_object_retention.return_value["VersionId"] = "other"
    assert run(sample)["reason"] == "retention_version_mismatch"


def test_missing_metadata_denied(sample):
    sample[1].get_object_retention.return_value = {}
    assert run(sample)["reason"] == "missing_retention_or_hold"


def test_provider_error_denied(sample):
    sample[1].get_object_retention.side_effect = RuntimeError("permission denied")
    assert run(sample)["reason"] == "retention_metadata_read_failed"


def test_invalid_threshold(sample):
    with pytest.raises(ValueError):
        run(sample, minimum_retention_days=0)
