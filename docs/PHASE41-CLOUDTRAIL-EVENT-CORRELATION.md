# Phase 41 — Provider audit-event structure and correlation

This offline validator accepts bounded CloudTrail-style JSON with a
`Records` array and requires exactly one S3 `DeleteObject` event
with `AccessDenied`, matching recipient account, bucket, key, object
version, request ID and a recent timezone-aware timestamp. It can
pin the SHA-256 digest of exact log bytes and correlate request IDs
with a successful Phase 40 independent audit-evidence result.

**Security boundary:** a JSON object that resembles a CloudTrail event
is **not authenticated provider-origin evidence**. Even an exact
SHA-256 match only establishes byte integrity relative to a trusted
digest. Production validation must independently retrieve provider
CloudTrail log files, verify CloudTrail digest-chain continuity and
AWS-signed digest signatures with the correct region/public key,
establish trustworthy log custody and validate real-world deletion
denial on an approved disposable object. None of those live checks
are performed here. No production authorization is implied.
