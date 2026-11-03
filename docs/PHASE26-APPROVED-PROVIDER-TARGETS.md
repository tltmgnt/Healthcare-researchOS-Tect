# Phase 26 — Approved provider target enforcement

`run_approved_provider_validation(storage_client, identity_client,
approved_account_id=..., approved_buckets=..., **validation_args)`
wraps the Phase 25 read-only runner with an explicit STS-style
`get_caller_identity()` account check and exact bucket allowlist.
The runner refuses disabled, production-labelled, unapproved, or
unidentified targets before making any S3 object calls.

Supply the approved 12-digit account ID and bucket allowlist from an
independently reviewed change record, **not** from the same untrusted
runtime configuration as the target. Inject separate S3 and STS clients.
The returned report records the verified account ID and allowlist.

**Important boundaries:** a reported account ID does not prove that the
endpoint is authentic or that the client credentials are read-only.
Enforce least-privilege IAM and endpoint controls outside this module.
The caller-provided non-production label and allowlist are not sufficient
to establish real-world environment classification. No deletion tests
or live-provider requests are executed by unit tests.
