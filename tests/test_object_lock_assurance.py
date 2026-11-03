import pytest
from tect.object_lock_assurance import inspect_anchor_bucket


class Fake:
    def __init__(self, status="Enabled", enabled="Enabled", mode="COMPLIANCE", days=365):
        self.status, self.enabled, self.mode, self.days = status, enabled, mode, days

    def get_bucket_versioning(self, *, Bucket):
        return {"Status": self.status}

    def get_object_lock_configuration(self, *, Bucket):
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": self.enabled,
            "Rule": {"DefaultRetention": {"Mode": self.mode, "Days": self.days}}}}


def test_compliance_bucket_passes():
    assert inspect_anchor_bucket(Fake(), "bucket")["ready"]


def test_versioning_disabled():
    report = inspect_anchor_bucket(Fake(status="Suspended"), "bucket")
    assert not report["ready"]
    assert not report["checks"]["versioning_enabled"]


def test_governance_mode_fails():
    assert not inspect_anchor_bucket(Fake(mode="GOVERNANCE"), "bucket")["ready"]


def test_short_retention_fails():
    assert not inspect_anchor_bucket(Fake(days=30), "bucket")["ready"]


def test_missing_lock_fails():
    assert not inspect_anchor_bucket(Fake(enabled=None), "bucket")["ready"]


def test_provider_failure_fails_closed():
    class Failing:
        def get_bucket_versioning(self, **kwargs):
            raise PermissionError("Denied")
    report = inspect_anchor_bucket(Failing(), "bucket")
    assert not report["ready"]
    assert report["reason"] == "bucket_inspection_failed"


def test_years_retention():
    class Years(Fake):
        def get_object_lock_configuration(self, *, Bucket):
            return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Years": 2}}}}
    assert inspect_anchor_bucket(Years(), "bucket", minimum_retention_days=730)["ready"]


def test_invalid_minimum():
    with pytest.raises(ValueError):
        inspect_anchor_bucket(Fake(), "bucket", minimum_retention_days=0)


def test_read_only_calls():
    client = Fake()
    assert inspect_anchor_bucket(client, "bucket")["ready"]
