from tect.readonly_permission_preflight import (
    FORBIDDEN_ACTIONS, REQUIRED_READ_ACTIONS, inspect_readonly_configuration
)


def check(**overrides):
    args = dict(endpoint_url="https://s3.example.test",
                approved_endpoint_urls={"https://s3.example.test"},
                declared_allowed_actions=set(REQUIRED_READ_ACTIONS),
                declared_denied_actions=set(FORBIDDEN_ACTIONS))
    args.update(overrides)
    return inspect_readonly_configuration(**args)


def test_approved_configuration():
    assert check()["ready"]


def test_unapproved_endpoint():
    assert not check(endpoint_url="https://other.example.test")["ready"]


def test_http_rejected():
    assert not check(endpoint_url="http://s3.example.test",
                     approved_endpoint_urls={"http://s3.example.test"})["ready"]


def test_endpoint_credentials_rejected():
    assert not check(endpoint_url="https://user:password@s3.example.test",
                     approved_endpoint_urls={"https://user:password@s3.example.test"})["ready"]


def test_query_rejected():
    assert not check(endpoint_url="https://s3.example.test?token=secret",
                     approved_endpoint_urls={"https://s3.example.test?token=secret"})["ready"]


def test_missing_read_action():
    assert not check(declared_allowed_actions=set(REQUIRED_READ_ACTIONS) - {"s3:GetObjectVersion"})["ready"]


def test_missing_explicit_deny():
    assert not check(declared_denied_actions=set(FORBIDDEN_ACTIONS) - {"s3:DeleteObject"})["ready"]


def test_wildcard_allow_rejected():
    assert not check(declared_allowed_actions=set(REQUIRED_READ_ACTIONS) | {"s3:*"})["ready"]


def test_invalid_policy_type():
    assert not check(declared_allowed_actions=["s3:GetObject"])["ready"]


def test_invalid_endpoint_type():
    assert not check(endpoint_url=None)["ready"]
