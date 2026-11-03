"""Offline endpoint and IAM-policy preflight for approved read-only audits.

Checks caller-supplied configuration, not effective AWS permissions.
"""
from urllib.parse import urlsplit

REQUIRED_READ_ACTIONS = frozenset({
    "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention",
    "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration",
})
FORBIDDEN_ACTIONS = frozenset({
    "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion",
    "s3:PutObjectRetention", "s3:PutObjectLegalHold",
    "s3:BypassGovernanceRetention", "s3:PutBucketObjectLockConfiguration",
    "s3:PutBucketVersioning", "s3:*", "*",
})


def inspect_readonly_configuration(*, endpoint_url: str,
                                   approved_endpoint_urls: set[str],
                                   declared_allowed_actions: set[str],
                                   declared_denied_actions: set[str]) -> dict:
    """Require exact HTTPS endpoint approval and explicit deny declarations.

    Never grants or probes permissions; requires out-of-band effective-policy
    validation and credential-scoped IAM enforcement.
    """
    checks = {"endpoint_approved": False, "https_endpoint": False,
              "read_actions_declared": False, "mutations_denied": False,
              "no_wildcard_allow": False}
    if not isinstance(endpoint_url, str) or not isinstance(approved_endpoint_urls, (set, frozenset)):
        return {"ready": False, "checks": checks, "reason": "invalid_endpoint_configuration"}
    parsed = urlsplit(endpoint_url)
    checks["https_endpoint"] = (parsed.scheme == "https" and bool(parsed.hostname)
                                and not parsed.username and not parsed.password
                                and not parsed.query and not parsed.fragment
                                and parsed.path in ("", "/"))
    checks["endpoint_approved"] = (checks["https_endpoint"] and endpoint_url in approved_endpoint_urls)
    if not isinstance(declared_allowed_actions, (set, frozenset)) or not isinstance(declared_denied_actions, (set, frozenset)):
        return {"ready": False, "checks": checks, "reason": "invalid_policy_declarations"}
    checks["read_actions_declared"] = REQUIRED_READ_ACTIONS.issubset(declared_allowed_actions)
    checks["mutations_denied"] = FORBIDDEN_ACTIONS.issubset(declared_denied_actions)
    checks["no_wildcard_allow"] = not bool(declared_allowed_actions & FORBIDDEN_ACTIONS)
    return {"ready": all(checks.values()), "checks": checks,
            "limitations": "Static declarations only; effective IAM permissions, TLS trust and credential identity unverified"}
