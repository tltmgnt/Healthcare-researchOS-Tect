# Phase 38 — Provider retention assurance for floor anchors

Extends Phase 37's approved, version-pinned, read-only S3-compatible
retrieval and signature verification with per-object retention evidence.

The adapter reads `get_object_retention` and
`get_object_legal_hold` for the **same exact object version**,
requires Object Lock `COMPLIANCE` mode, at least 30 days of remaining
retention (configurable), and legal hold `ON`. It rejects missing,
inconsistent, expired or insufficient metadata and cloud API failures.

The existing Phase 37 opt-in, non-production environment, approval,
account and bucket allowlists still apply before any provider calls.

**Limitations:** these are provider-reported read-only metadata checks.
They do not demonstrate a denied deletion attempt, prove effective IAM
permissions, validate independent cloud account custody, or establish
the provider's trustworthiness. Do not run destructive validation
without separate authorization and disposable test resources.
