# Phase 40 — Independent provider audit-evidence verification

Read-only, non-production, approval-gated retrieval of a version-pinned
audit artifact from a **separate approved cloud account**. The adapter
checks the caller account before reading, requires an exact object
version, limits bytes to 2 MiB and compares the retrieved bytes to the
Phase 39 independently signed deletion-denial artifact and its SHA-256
digest.

A normalized audit JSON record must identify the exact protected
account, bucket, key and object version, approval reference, a
`DeleteObjectVersion` attempt with `AccessDenied` outcome, a request
ID and a recent timezone-aware event timestamp.

**Important:** a normalized JSON record is not a provider-authenticated
CloudTrail log. The current verifier cannot prove the event came from
the provider or that the deletion denial was actually enforced. An
independent reviewer must authenticate provider-generated records and
custody, correlate request IDs with provider logs, verify Object Lock
settings and approve any disposable-resource deletion exercise.
No destructive cloud operation is performed by this code.
