# Phase 2: API authentication and role authorization

This is **prototype security hardening**, not production or clinical certification.

## Configuration

Generate a unique high-entropy token for each principal (at least 32 random bytes).
Store only SHA-256 token digests in the JSON mapping supplied by `TECT_API_KEYS_JSON`.
Example setup (local shell; never commit the generated token or mapping):

```bash
python - <<'PY'
import hashlib, json, secrets
token = secrets.token_urlsafe(48)
print("Save this token securely:", token)
print("TECT_API_KEYS_JSON=" + json.dumps({hashlib.sha256(token.encode()).hexdigest(): "admin"}))
PY
```

Set the generated JSON as the environment variable `TECT_API_KEYS_JSON` in a protected secret manager.
Clients must send `Authorization: Bearer <token>` to all endpoints except `GET /health`.
Missing or malformed configuration returns HTTP 503 (fail closed).
Missing or invalid credentials return 401; insufficient role permissions return 403.

| Role | Read claims and assessments | Create/revise claims | Verify audit chain |
| --- | --- | --- | --- |
| reader | Yes | No | No |
| writer | Yes | Yes | No |
| auditor | Yes | No | Yes |
| admin | Yes | Yes | Yes |

Tokens are shared static bearer credentials. Rotate tokens by changing the environment mapping
and restarting the service; use TLS and avoid logging Authorization headers.

## Verification

```bash
python -m pip install -e ".[dev]"
pytest -q
```

## Explicit limitations and next work

- This is process-local authentication with static tokens, not OIDC, SSO, MFA, or user identity.
- No per-claim ownership, tenant isolation, rate limiting, key revocation endpoint, or security event ledger.
- OpenAPI documentation is not protected by this change; do not publish service publicly.
- A bearer token is sufficient to impersonate its holder if stolen. Use HTTPS and a trusted reverse proxy.
- SQLite is not encrypted at rest. No PHI, clinical workflows, or public deployment.
- SHA-256 audit chains are not externally anchored; privileged history rewriting remains possible.
- Caller-supplied evidence verification is not independent scientific provenance verification.
- Review existing deployment scripts and CI before adoption. Conduct external security review.
