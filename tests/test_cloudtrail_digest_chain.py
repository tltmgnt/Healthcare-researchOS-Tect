import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from tect.cloudtrail_digest_chain import verify_pinned_digest_chain

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)
GENESIS = "a" * 64


def chain():
    paths = ["digest-1.json", "digest-2.json"]
    first = {
        "digestS3Object": paths[0], "previousDigestHashValue": GENESIS,
        "previousDigestS3Object": "trusted-before.json",
        "digestStartTime": (NOW - timedelta(hours=2)).isoformat(),
        "digestEndTime": (NOW - timedelta(hours=1)).isoformat()}
    one = json.dumps(first, sort_keys=True).encode()
    second = {
        "digestS3Object": paths[1], "previousDigestHashValue": hashlib.sha256(one).hexdigest(),
        "previousDigestS3Object": paths[0],
        "digestStartTime": (NOW - timedelta(hours=1)).isoformat(),
        "digestEndTime": NOW.isoformat()}
    two = json.dumps(second, sort_keys=True).encode()
    return [one, two], paths


def run(raw=None, paths=None, **overrides):
    if raw is None:
        raw, default_paths = chain()
    else:
        default_paths = ["digest-1.json", "digest-2.json"]
    if paths is None:
        paths = default_paths
    args = dict(expected_paths=paths, expected_sha256=[hashlib.sha256(x).hexdigest() for x in raw],
                trusted_initial_previous_hash=GENESIS, checked_at=NOW)
    args.update(overrides)
    return verify_pinned_digest_chain(raw, **args)


def test_valid_chain():
    assert run()["valid"]


def test_final_digest_returned():
    raw, _ = chain()
    assert run(raw)["final_digest_sha256"] == hashlib.sha256(raw[-1]).hexdigest()


def test_tampered_digest_pin():
    assert run(expected_sha256=["0" * 64] * 2)["reason"] == "digest_pin_mismatch"


def test_predecessor_hash_mismatch():
    raw, paths = chain()
    record = json.loads(raw[1])
    record["previousDigestHashValue"] = "b" * 64
    raw[1] = json.dumps(record).encode()
    assert run(raw, paths)["reason"] == "predecessor_hash_mismatch"


def test_predecessor_path_mismatch():
    raw, paths = chain()
    record = json.loads(raw[1])
    record["previousDigestS3Object"] = "other"
    raw[1] = json.dumps(record).encode()
    assert run(raw, paths)["reason"] == "predecessor_path_mismatch"


def test_interval_gap():
    raw, paths = chain()
    record = json.loads(raw[1])
    record["digestStartTime"] = (NOW - timedelta(minutes=30)).isoformat()
    raw[1] = json.dumps(record).encode()
    assert run(raw, paths)["reason"] == "noncontiguous_interval"


def test_duplicate_paths():
    assert run(paths=["same", "same"])["reason"] == "invalid_expected_pins"


def test_missing_initial_pin():
    assert run(trusted_initial_previous_hash="")["reason"] == "invalid_initial_pin"


def test_single_digest_denied():
    raw, paths = chain()
    assert run(raw[:1], paths[:1])["reason"] == "invalid_chain_length"


def test_reversed_digest_order():
    raw, paths = chain()
    assert run(list(reversed(raw)), paths)["reason"] == "digest_path_mismatch"


def test_wrong_digest_path():
    assert run(paths=["wrong", "digest-2.json"])["reason"] == "digest_path_mismatch"


def test_invalid_json():
    raw, paths = chain()
    raw[1] = b"{"
    assert run(raw, paths)["reason"] == "invalid_digest_json"


def test_stale_interval():
    raw, paths = chain()
    assert run(raw, paths, checked_at=NOW + timedelta(days=100))["reason"] == "stale_or_future_digest"


def test_naive_checked_at():
    with pytest.raises(ValueError):
        run(checked_at=datetime(2026, 11, 3))


def test_future_interval():
    raw, paths = chain()
    assert run(raw, paths, checked_at=NOW - timedelta(hours=3))["reason"] == "stale_or_future_digest"
