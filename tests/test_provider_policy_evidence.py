from copy import deepcopy
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tect.provider_policy_evidence import (
    REQUIRED_ASSERTIONS, sign_policy_assessment, verify_policy_assessment
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
REPORT = b"synthetic provider IAM assessment report"


@pytest.fixture
def signed():
    key = Ed25519PrivateKey.generate()
    envelope = sign_policy_assessment(
        REPORT, account_id="123456789012", approval_reference="CHG-42",
        reviewer_key_id="independent", assertions={k: True for k in REQUIRED_ASSERTIONS},
        private_key=key, assessed_at=NOW)
    return envelope, key


def verify(signed, *, envelope=None, report=REPORT, keys=None, account="123456789012", approval="CHG-42"):
    original, key = signed
    return verify_policy_assessment(
        original if envelope is None else envelope, report,
        {"independent": key.public_key()} if keys is None else keys,
        expected_account_id=account, expected_approval_reference=approval)


def test_valid_signed_report(signed):
    assert verify(signed)["valid"]


def test_modified_report_rejected(signed):
    assert verify(signed, report=REPORT + b"!")["reason"] == "report_digest_mismatch"


def test_wrong_account_rejected(signed):
    assert verify(signed, account="999999999999")["reason"] == "scope_mismatch"


def test_wrong_approval_rejected(signed):
    assert verify(signed, approval="CHG-99")["reason"] == "scope_mismatch"


def test_untrusted_reviewer_rejected(signed):
    assert verify(signed, keys={})["reason"] == "untrusted_reviewer"


def test_modified_signature_rejected(signed):
    envelope = deepcopy(signed[0])
    envelope["signature_hex"] = "0" * 128
    assert verify(signed, envelope=envelope)["reason"] == "signature_mismatch"


def test_modified_assertion_rejected(signed):
    envelope = deepcopy(signed[0])
    envelope["assertions"]["effective_mutating_permissions_denied"] = False
    assert verify(signed, envelope=envelope)["reason"] == "invalid_envelope"


def test_missing_assertion_refuses_signing(signed):
    key = signed[1]
    assertions = {k: True for k in REQUIRED_ASSERTIONS}
    del assertions["independent_reviewer_confirmed"]
    with pytest.raises(ValueError):
        sign_policy_assessment(REPORT, account_id="123456789012", approval_reference="CHG-42",
                               reviewer_key_id="independent", assertions=assertions, private_key=key)


def test_oversized_report_refuses_signing(signed):
    with pytest.raises(ValueError):
        sign_policy_assessment(b"x" * (2 * 1024 * 1024 + 1),
                               account_id="123456789012", approval_reference="CHG-42",
                               reviewer_key_id="independent",
                               assertions={k: True for k in REQUIRED_ASSERTIONS},
                               private_key=signed[1])


def test_naive_date_refuses_signing(signed):
    with pytest.raises(ValueError):
        sign_policy_assessment(REPORT, account_id="123456789012", approval_reference="CHG-42",
                               reviewer_key_id="independent",
                               assertions={k: True for k in REQUIRED_ASSERTIONS},
                               private_key=signed[1], assessed_at=datetime(2026, 1, 1))
