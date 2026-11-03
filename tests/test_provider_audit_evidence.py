import hashlib
import io
import json
from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.independent_custody_evidence import CONTROLS, SCHEMA as ASSESSMENT_SCHEMA, sign_custody_assessment
from tect.provider_audit_evidence import SCHEMA, verify_independent_provider_audit

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


@pytest.fixture
def sample():
    signer = Ed25519PrivateKey.generate()
    record = dict(schema=SCHEMA, account_id="123456789012", bucket="protected",
                  key="registry/floor.json", version_id="v1", action="DeleteObjectVersion",
                  outcome="AccessDenied", event_time=NOW.isoformat(),
                  request_id="req-123", approval_reference="CAB-123")
    raw = json.dumps(record, sort_keys=True).encode()
    artifacts = {c: (raw if c == "protected_version_deletion_denied" else c.encode()) for c in CONTROLS}
    payload = {
        "schema": ASSESSMENT_SCHEMA, "assessor_key_id": "auditor", "assessor_id": "independent-auditor",
        "operator_id": "operator", "approved_account_id": "123456789012",
        "bucket": "protected", "key": "registry/floor.json", "version_id": "v1",
        "approval_reference": "CAB-123", "assessed_at": NOW.isoformat(),
        "controls": {c: {"passed": True, "reference": "evidence://" + c,
                         "sha256": hashlib.sha256(artifacts[c]).hexdigest()} for c in CONTROLS}}
    envelope = sign_custody_assessment(payload, artifacts, assessor_private_key=signer, checked_at=NOW)
    storage, identity = Mock(), Mock()
    storage.get_object.return_value = {"VersionId": "audit-v1", "Body": io.BytesIO(raw)}
    identity.get_caller_identity.return_value = {"Account": "999999999999"}
    return signer, envelope, artifacts, storage, identity, raw


def run(sample, **overrides):
    signer, envelope, artifacts, storage, identity, raw = sample
    storage.get_object.return_value["Body"] = io.BytesIO(raw)
    args = dict(audit_bucket="audit-bucket", audit_key="audit.json",
                audit_version_id="audit-v1", approved_audit_buckets={"audit-bucket"},
                approved_audit_account_id="999999999999",
                protected_account_id="123456789012", protected_bucket="protected",
                protected_key="registry/floor.json", protected_version_id="v1",
                expected_operator_id="operator", assessment_envelope=envelope,
                assessment_artifacts=artifacts, trusted_assessors={"auditor": signer.public_key()},
                checked_at=NOW, approval_reference="CAB-123",
                enabled=True, environment="non-production")
    args.update(overrides)
    return verify_independent_provider_audit(storage, identity, **args)


def test_valid(sample):
    assert run(sample)["ready"]


def test_opt_in_required(sample):
    assert run(sample, enabled=False)["reason"] == "explicit_opt_in_required"
    sample[4].get_caller_identity.assert_not_called()


def test_production_denied(sample):
    assert run(sample, environment="production")["reason"] == "non_production_only"


def test_separate_account_required(sample):
    assert run(sample, approved_audit_account_id="123456789012")["reason"] == "independent_account_required"


def test_audit_bucket_allowlist(sample):
    assert run(sample, audit_bucket="unapproved")["reason"] == "audit_bucket_not_approved"


def test_wrong_caller_account(sample):
    sample[4].get_caller_identity.return_value = {"Account": "000000000000"}
    assert run(sample)["reason"] == "audit_account_not_approved"
    sample[3].get_object.assert_not_called()


def test_wrong_object_version(sample):
    sample[3].get_object.return_value["VersionId"] = "wrong"
    assert run(sample)["reason"] == "audit_version_mismatch"


def test_tampered_audit_bytes(sample):
    sample = (*sample[:5], b"tampered")
    assert run(sample)["reason"] == "signed_audit_digest_mismatch"


def test_invalid_assessor_signature(sample):
    sample[1]["signature_hex"] = "0" * 128
    assert run(sample)["reason"] == "signed_assessment_invalid"


def test_wrong_protected_version(sample):
    assert run(sample, protected_version_id="v2")["reason"] == "signed_assessment_invalid"


def test_missing_approval(sample):
    assert run(sample, approval_reference="")["reason"] == "approval_required"


def test_provider_failure(sample):
    sample[3].get_object.side_effect = RuntimeError("denied")
    assert run(sample)["reason"] == "audit_retrieval_failed"


def test_audit_event_denial_required(sample):
    record = json.loads(sample[5])
    record["outcome"] = "Success"
    raw = json.dumps(record, sort_keys=True).encode()
    # Signature still binds original bytes, so a substituted event is rejected.
    sample = (*sample[:5], raw)
    assert run(sample)["reason"] == "signed_audit_digest_mismatch"
