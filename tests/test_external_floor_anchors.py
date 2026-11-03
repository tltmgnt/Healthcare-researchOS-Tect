from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.durable_registry_floor import RegistryFloorStore
from tect.external_floor_anchors import (
    sign_floor_anchor, verify_floor_anchor, verify_local_floor_against_anchor
)

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


@pytest.fixture
def sample(tmp_path):
    store = RegistryFloorStore.provision(str(tmp_path / "floor.db"), initial_sequence=7)
    key = Ed25519PrivateKey.generate()
    anchor = sign_floor_anchor(store, authority_key_id="security-root",
                               private_key=key, created_at=NOW)
    return store, key, anchor


def verify(sample, **kwargs):
    return verify_floor_anchor(sample[2], {"security-root": sample[1].public_key()},
                               independently_pinned_sequence=7, checked_at=NOW, **kwargs)


def test_valid_anchor(sample):
    assert verify(sample)["valid"]


def test_local_matches_anchor(sample):
    result = verify_local_floor_against_anchor(
        sample[0], sample[2], {"security-root": sample[1].public_key()},
        independently_pinned_sequence=7, checked_at=NOW)
    assert result["ready"]


def test_local_floor_ahead(sample):
    sample[0].compare_and_advance(expected_floor=7, new_sequence=8)
    result = verify_local_floor_against_anchor(
        sample[0], sample[2], {"security-root": sample[1].public_key()},
        independently_pinned_sequence=7, checked_at=NOW)
    assert result["ready"] and result["local_sequence"] == 8


def test_local_rollback_detected(sample, tmp_path):
    other = RegistryFloorStore.provision(str(tmp_path / "older.db"), initial_sequence=6)
    result = verify_local_floor_against_anchor(
        other, sample[2], {"security-root": sample[1].public_key()},
        independently_pinned_sequence=7, checked_at=NOW)
    assert result["reason"] == "local_floor_rollback"


def test_anchor_rollback_detected(sample):
    result = verify_floor_anchor(sample[2], {"security-root": sample[1].public_key()},
                                 independently_pinned_sequence=8, checked_at=NOW)
    assert result["reason"] == "anchor_rollback"


def test_modified_anchor_sequence(sample):
    anchor = dict(sample[2])
    anchor["minimum_sequence"] = 8
    assert not verify_floor_anchor(anchor, {"security-root": sample[1].public_key()},
                                   independently_pinned_sequence=7, checked_at=NOW)["valid"]


def test_modified_signature(sample):
    anchor = dict(sample[2])
    anchor["signature_hex"] = "0" * 128
    assert not verify_floor_anchor(anchor, {"security-root": sample[1].public_key()},
                                   independently_pinned_sequence=7, checked_at=NOW)["valid"]


def test_unknown_authority(sample):
    assert not verify_floor_anchor(sample[2], {}, independently_pinned_sequence=7,
                                   checked_at=NOW)["valid"]


def test_future_anchor(sample):
    assert not verify_floor_anchor(sample[2], {"security-root": sample[1].public_key()},
                                   independently_pinned_sequence=7,
                                   checked_at=NOW - timedelta(seconds=1))["valid"]


def test_invalid_floor(sample):
    with pytest.raises(ValueError):
        verify_floor_anchor(sample[2], {"security-root": sample[1].public_key()},
                            independently_pinned_sequence=0, checked_at=NOW)


def test_naive_created_at(sample):
    with pytest.raises(ValueError):
        sign_floor_anchor(sample[0], authority_key_id="security-root",
                          private_key=sample[1], created_at=datetime(2026, 11, 3))


def test_missing_database(sample, tmp_path):
    missing = RegistryFloorStore(str(tmp_path / "missing.db"))
    with pytest.raises(FileNotFoundError):
        sign_floor_anchor(missing, authority_key_id="security-root",
                          private_key=sample[1], created_at=NOW)
