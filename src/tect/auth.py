"""Fail-closed bearer-token authentication for a single-instance research prototype.

TECT_API_KEYS_JSON maps SHA-256 digests of high-entropy tokens to roles.
Never store plaintext tokens in the configuration or repository.
"""
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request

ROLES = {"reader", "writer", "auditor", "admin"}
PERMISSIONS = {
    "reader": {"read"},
    "writer": {"read", "write"},
    "auditor": {"read", "audit"},
    "admin": {"read", "write", "audit"},
}
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Principal:
    role: str
    token_digest: str


def _configured_keys() -> dict[str, str]:
    raw = os.environ.get("TECT_API_KEYS_JSON")
    if not raw:
        raise HTTPException(status_code=503, detail="Authentication is not configured")
    try:
        keys = json.loads(raw)
        if (not isinstance(keys, dict) or not keys
                or any(not isinstance(k, str) or not HEX_SHA256.fullmatch(k)
                       or v not in ROLES for k, v in keys.items())):
            raise ValueError("Invalid authentication configuration")
    except (ValueError, TypeError):
        raise HTTPException(status_code=503, detail="Invalid authentication configuration")
    return keys


def authenticate(request: Request) -> Principal:
    keys = _configured_keys()
    header = request.headers.get("authorization", "")
    scheme, separator, token = header.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token or len(token) > 4096:
        raise HTTPException(
            status_code=401, detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    role = None
    # Compare against every configured digest to avoid early-exit matching.
    for stored_digest, stored_role in keys.items():
        if hmac.compare_digest(digest, stored_digest):
            role = stored_role
    if role is None:
        raise HTTPException(
            status_code=401, detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Principal(role=role, token_digest=digest)


def require(permission: str):
    def check(principal: Principal = Depends(authenticate)) -> Principal:
        if permission not in PERMISSIONS[principal.role]:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return principal
    return check
