# Phase 17 — Opt-in composite anchor object publication

`tect.composite_object_storage.publish_composite_anchor(client, bucket, key,
private_key, key_id)` signs the **claim and DOI verification histories** and
uploads the resulting JSON to an S3-compatible object store using
`IfNoneMatch="*"`. It returns a SHA-256 digest and, when supplied by the
provider, an object version ID.

`retrieve_and_verify_composite_anchor(client, bucket, key,
trusted_public_keys, expected_sha256=..., version_id=...)` retrieves a bounded
object, checks the independently supplied digest, validates the Ed25519
signature and both historical chain prefixes.

The S3 client is injected; no cloud credentials are embedded or network calls
are performed during unit tests.

## Operator assurance requirements

- Configure bucket versioning, Object Lock compliance-mode retention, access
  policies and retention periods in the real provider; **this code does not
  enforce or attest to Object Lock**.
- Retain the returned digest and version ID **outside the database trust
  boundary** and independently provision trusted public keys.
- Test with real provider permissions, conditional writes, retention policies,
  restore/retrieval procedures and credential rotation before production use.
- Do not store sensitive clinical content in object keys. Anchors contain
  chain heads and counts, not excerpts or research payloads.

This adapter is a capability for immutable publication, **not proof that any
external immutable copy currently exists**.
