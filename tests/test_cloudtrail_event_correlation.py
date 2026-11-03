import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from tect.cloudtrail_event_correlation import validate_cloudtrail_denial, correlate_provider_denial

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)
ACCOUNT = "123456789012"
BUCKET = "protected"
KEY = "registry/floor.json"
VERSION = "v1"
REQUEST = "req-123"


def event(**overrides):
    value = {"eventSource": "s3.amazonaws.com", "eventName": "DeleteObject",
             "errorCode": "AccessDenied", "recipientAccountId": ACCOUNT,
             "requestID": REQUEST, "eventTime": NOW.isoformat(),
             "requestParameters": {"bucketName": BUCKET, "key": KEY, "versionId": VERSION}}
    value.update(overrides)
    return value


def raw(*records):
    return json.dumps({"Records": list(records)}).encode()


def check(data, **overrides):
    args = dict(expected_account_id=ACCOUNT, expected_bucket=BUCKET,
                expected_key=KEY, expected_version_id=VERSION,
                expected_request_id=REQUEST, checked_at=NOW)
    args.update(overrides)
    return validate_cloudtrail_denial(data, **args)


def test_valid_event():
    assert check(raw(event()))["valid"]


def test_digest_pinning():
    data = raw(event())
    assert check(data, expected_sha256=hashlib.sha256(data).hexdigest())["valid"]


def test_wrong_digest():
    assert check(raw(event()), expected_sha256="0" * 64)["reason"] == "log_digest_mismatch"


def test_wrong_account():
    assert not check(raw(event(recipientAccountId="000000000000")))["valid"]


def test_wrong_object_version():
    assert not check(raw(event(requestParameters={"bucketName": BUCKET, "key": KEY, "versionId": "v2"})))["valid"]


def test_success_not_denial():
    assert not check(raw(event(errorCode=None)))["valid"]


def test_wrong_request_id():
    assert not check(raw(event(requestID="different")))["valid"]


def test_duplicate_event_rejected():
    assert check(raw(event(), event()))["reason"] == "unique_matching_denial_required"


def test_future_event():
    assert check(raw(event(eventTime=(NOW + timedelta(days=1)).isoformat())))["reason"] == "stale_or_future_event"


def test_old_event():
    assert check(raw(event(eventTime=(NOW - timedelta(days=100)).isoformat())))["reason"] == "stale_or_future_event"


def test_invalid_json():
    assert check(b"{")["reason"] == "invalid_json"


def test_oversize():
    assert check(b"x" * (2 * 1024 * 1024 + 1))["reason"] == "invalid_or_oversize_log"


def test_phase40_required():
    assert not correlate_provider_denial(
        {"ready": False}, raw(event()), expected_account_id=ACCOUNT,
        expected_bucket=BUCKET, expected_key=KEY,
        expected_version_id=VERSION, checked_at=NOW,
        expected_cloudtrail_sha256="0" * 64)["valid"]


def test_correlated_request():
    data = raw(event())
    result = correlate_provider_denial(
        {"schema": "tect.provider-audit-evidence.v1", "ready": True,
         "request_id": REQUEST, "protected_version_id": VERSION},
        data, expected_account_id=ACCOUNT, expected_bucket=BUCKET,
        expected_key=KEY, expected_version_id=VERSION, checked_at=NOW,
        expected_cloudtrail_sha256=hashlib.sha256(data).hexdigest())
    assert result["valid"]


def test_correlated_version_mismatch():
    assert correlate_provider_denial(
        {"schema": "tect.provider-audit-evidence.v1", "ready": True,
         "request_id": REQUEST, "protected_version_id": "v2"},
        raw(event()), expected_account_id=ACCOUNT, expected_bucket=BUCKET,
        expected_key=KEY, expected_version_id=VERSION, checked_at=NOW,
        expected_cloudtrail_sha256="0" * 64)["reason"] == "protected_version_mismatch"
