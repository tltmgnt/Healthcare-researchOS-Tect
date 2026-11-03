from datetime import datetime, timedelta, timezone
import pytest
from tect.object_retention_evidence import inspect_anchor_retention

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Fake:
    def __init__(self, mode="COMPLIANCE", days=400, until=None):
        self.mode, self.days, self.until = mode, days, until
        self.calls = []

    def get_object_retention(self, **kwargs):
        self.calls.append(kwargs)
        return {"Retention": {"Mode": self.mode,
                "RetainUntilDate": self.until if self.until is not None else NOW + timedelta(days=self.days)}}


def check(client, **kwargs):
    return inspect_anchor_retention(client, "bucket", "anchors/a.json", "version-1", now=NOW, **kwargs)


def test_valid_version_retention():
    client = Fake()
    result = check(client)
    assert result["ready"]
    assert client.calls == [{"Bucket": "bucket", "Key": "anchors/a.json", "VersionId": "version-1"}]


def test_governance_fails():
    assert not check(Fake(mode="GOVERNANCE"))["ready"]


def test_short_retention_fails():
    assert not check(Fake(days=30))["ready"]


def test_exact_minimum_passes():
    assert check(Fake(days=365))["ready"]


def test_naive_datetime_fails():
    assert check(Fake(until=datetime(2027, 1, 1)))["reason"] == "invalid_retention_date"


def test_provider_error_fails_closed():
    class Broken:
        def get_object_retention(self, **kwargs):
            raise PermissionError("denied")
    assert check(Broken())["reason"] == "retention_inspection_failed"


def test_version_id_required():
    with pytest.raises(ValueError):
        inspect_anchor_retention(Fake(), "bucket", "key", "")


def test_invalid_minimum():
    with pytest.raises(ValueError):
        check(Fake(), minimum_remaining_days=0)


def test_naive_now_rejected():
    with pytest.raises(ValueError):
        inspect_anchor_retention(Fake(), "bucket", "key", "v", now=datetime(2026, 1, 1))
