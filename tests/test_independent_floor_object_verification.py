import io
import json
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.durable_registry_floor import RegistryFloorStore
from tect.external_floor_anchors import sign_floor_anchor
from tect.independent_floor_object_verification import verify_pinned_floor_object

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)
ACCOUNT = "123456789012"


@pytest.fixture
def setup(tmp_path):
    store = RegistryFloorStore.provision(str(tmp_path / "floor.db"), initial_sequence=7)
    signer = Ed25519PrivateKey.generate()
    anchor = sign_floor_anchor(store, authority_key_id="root", private_key=signer, created_at=NOW)
    storage, identity = Mock(), Mock()
    storage.get_object.return_value = {"VersionId": "v1", "Body": io.BytesIO(json.dumps(anchor).encode())}
    identity.get_caller_identity.return_value = {"Account": ACCOUNT}
    return store, anchor, storage, identity, {"root": signer.public_key()}


def run(s, **overrides):
    store, anchor, storage, identity, keys = s
    args = dict(bucket="approved-bucket", key="floor.json", version_id="v1",
                approved_account_id=ACCOUNT, approved_buckets={"approved-bucket"},
                trusted_authorities=keys, independently_pinned_sequence=7,
                checked_at=NOW, approval_reference="CAB-123", enabled=True,
                environment="non-production", local_store=store)
    args.update(overrides)
    return verify_pinned_floor_object(storage, identity, **args)


def test_success(setup):
    assert run(setup)["ready"]


def test_no_opt_in_prevents_calls(setup):
    assert run(setup, enabled=False)["reason"] == "explicit_opt_in_required"
    setup[3].get_caller_identity.assert_not_called()


def test_production_denied_before_calls(setup):
    assert run(setup, environment="production")["reason"] == "non_production_only"
    setup[3].get_caller_identity.assert_not_called()


def test_wrong_bucket_denied_before_calls(setup):
    assert run(setup, bucket="unapproved")["reason"] == "bucket_not_approved"
    setup[3].get_caller_identity.assert_not_called()


def test_missing_version_denied(setup):
    assert run(setup, version_id="")["reason"] == "version_pinned_object_required"


def test_wrong_account_blocks_object_read(setup):
    setup[3].get_caller_identity.return_value = {"Account": "000000000000"}
    assert run(setup)["reason"] == "account_not_approved"
    setup[2].get_object.assert_not_called()


def test_version_mismatch(setup):
    setup[2].get_object.return_value["VersionId"] = "v2"
    assert run(setup)["reason"] == "object_version_mismatch"


def test_anchor_tampering(setup):
    tampered = dict(setup[1])
    tampered["minimum_sequence"] = 8
    setup[2].get_object.return_value["Body"] = io.BytesIO(json.dumps(tampered).encode())
    assert not run(setup)["ready"]


def test_stale_external_pin(setup):
    assert not run(setup, independently_pinned_sequence=8)["ready"]


def test_oversize_body(setup):
    setup[2].get_object.return_value["Body"] = io.BytesIO(b"x" * 65537)
    assert run(setup)["reason"] == "invalid_or_oversize_anchor"


def test_provider_failure(setup):
    setup[2].get_object.side_effect = RuntimeError("denied")
    assert run(setup)["reason"] == "provider_read_failed"


def test_missing_approval(setup):
    assert run(setup, approval_reference="")["reason"] == "approval_required"


def test_local_floor_rollback(setup, tmp_path):
    old = RegistryFloorStore.provision(str(tmp_path / "older.db"), initial_sequence=6)
    assert run(setup, local_store=old)["reason"] == "local_floor_rollback"
