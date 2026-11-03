import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.durable_registry_floor import RegistryFloorStore, verify_release_with_durable_floor
from tect.release_gates import REQUIRED_GATES
from tect.signed_release_evidence import sign_release_evidence
from tect.signed_trust_registry import encode_reviewer_public_key, sign_trust_registry

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


def test_provision_and_read(tmp_path):
    store = RegistryFloorStore.provision(str(tmp_path / "floor.db"), initial_sequence=3)
    assert store.read() == 3


def test_cas_advances(tmp_path):
    store = RegistryFloorStore.provision(str(tmp_path / "floor.db"), initial_sequence=3)
    assert store.compare_and_advance(expected_floor=3, new_sequence=4)
    assert store.read() == 4


def test_stale_cas_rejected(tmp_path):
    store = RegistryFloorStore.provision(str(tmp_path / "floor.db"), initial_sequence=3)
    assert store.compare_and_advance(expected_floor=3, new_sequence=5)
    assert not store.compare_and_advance(expected_floor=3, new_sequence=6)
    assert store.read() == 5


def test_cannot_lower_floor(tmp_path):
    store = RegistryFloorStore.provision(str(tmp_path / "floor.db"), initial_sequence=3)
    with pytest.raises(ValueError):
        store.compare_and_advance(expected_floor=3, new_sequence=2)


def test_existing_file_provision_fails(tmp_path):
    path = str(tmp_path / "floor.db")
    RegistryFloorStore.provision(path, initial_sequence=3)
    with pytest.raises(FileExistsError):
        RegistryFloorStore.provision(path, initial_sequence=1)


def test_missing_database_fails_closed(tmp_path):
    with pytest.raises(FileNotFoundError):
        RegistryFloorStore(str(tmp_path / "missing.db")).read()


def test_corrupt_database_fails_closed(tmp_path):
    path = tmp_path / "bad.db"
    path.write_text("not a sqlite database")
    with pytest.raises((ValueError, Exception)):
        RegistryFloorStore(str(path)).read()


def test_in_memory_rejected():
    with pytest.raises(ValueError):
        RegistryFloorStore(":memory:")


@pytest.fixture
def sample(tmp_path):
    store = RegistryFloorStore.provision(str(tmp_path / "floor.db"), initial_sequence=5)
    authority, reviewer = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    entries = {"reviewer": {"public_key_hex": encode_reviewer_public_key(reviewer.public_key()),
              "reviewer_id": "review-board", "allowed_submitters": ["operator"],
              "allowed_gates": list(REQUIRED_GATES),
              "valid_from": (NOW - timedelta(days=2)).isoformat(),
              "valid_until": (NOW + timedelta(days=2)).isoformat(), "revoked": False}}
    registry = sign_trust_registry(entries, sequence=6,
                                   authority_key_id="root", authority_private_key=authority)
    artifacts = {gate: gate.encode() for gate in REQUIRED_GATES}
    gates = {gate: {"passed": True, "evidence_reference": "external://" + gate,
                    "evidence_sha256": hashlib.sha256(artifacts[gate]).hexdigest(),
                    "independent_approver": "review-board",
                    "approved_at": (NOW - timedelta(days=1)).isoformat()}
             for gate in REQUIRED_GATES}
    release = sign_release_evidence(gates, submitter_id="operator",
                                    reviewer_key_id="reviewer", private_key=reviewer, assessed_at=NOW)
    return store, release, artifacts, registry, {"root": authority.public_key()}


def run(sample, **kwargs):
    store, release, artifacts, registry, authorities = sample
    return verify_release_with_durable_floor(
        release, artifacts, registry, authorities, store,
        expected_submitter_id="operator", assessed_at=NOW, **kwargs)


def test_valid_release_advances_floor(sample):
    result = run(sample)
    assert result["release_evidence_ready"] and result["floor_advanced"]
    assert sample[0].read() == 6


def test_reverification_does_not_advance(sample):
    run(sample)
    result = run(sample)
    assert result["release_evidence_ready"] and not result["floor_advanced"]


def test_invalid_artifact_does_not_advance(sample):
    sample[2]["engineering_ci_and_review"] = b"altered"
    result = run(sample)
    assert not result["release_evidence_ready"] and sample[0].read() == 5


def test_rollback_after_advancement_rejected(sample):
    run(sample)
    sample[0].compare_and_advance(expected_floor=6, new_sequence=7)
    result = run(sample)
    assert not result["release_evidence_ready"]
    assert result["registry_reason"] == "registry_rollback"
    assert sample[0].read() == 7
