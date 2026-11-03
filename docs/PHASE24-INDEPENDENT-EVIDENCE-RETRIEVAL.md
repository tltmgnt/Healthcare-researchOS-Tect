# Phase 24 — Independent version-pinned evidence retrieval

`tect.independent_evidence_retrieval.verify_retrieved_evidence(client,
manifest, locations, trusted_public_keys)` fetches the six artifacts
associated with a signed Phase 23 evidence manifest from an injected
S3-compatible client.

Each control requires a nonempty `bucket`, `key`, and explicit
`version_id`. The verifier never silently fetches the latest version.
Retrieval is capped at 16 MiB + 1 byte per artifact and is fail-closed
on missing versions, provider errors, altered bytes, incomplete sets or
untrusted signing keys. It then verifies the signed checklist and manifest,
and matches the retrieved SHA-256 digests.

**Independent custody is an operator configuration requirement:** provision
the injected client against a separately administered evidence repository,
record version IDs out of band, and distribute reviewer public keys through
a trusted channel. This code does not independently authenticate the
provider, attest cloud account ownership, prove Object Lock enforcement,
or confirm the substantive truth of a report. All unit tests use a fake
provider and make no external network requests.
