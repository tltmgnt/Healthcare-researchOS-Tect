# Phase 31 — Verifiable release evidence (Production Assurance)

Phase 30 checks that each of nine release controls has an attestation.
Phase 31 additionally checks the **exact evidence bytes** supplied for
each gate, the declared SHA-256 digest, and the approval timestamp.

`verify_release_evidence(gates, artifacts, submitter_id=..., assessed_at=...)`
accepts a dictionary of gate records and a dictionary of corresponding
artifact bytes. Each gate requires Phase 30 attestation fields plus
`evidence_sha256` (lowercase SHA-256 hex). Default approval freshness is
90 days; configurable between 1 and 365 days. Evidence is limited to 2 MiB
per artifact. Missing, altered, oversized, stale, future-dated, self-approved
or unexpected artifacts fail closed.

**This is an offline integrity gate, not a production release permit.**
Approval identity is a string comparison, not independent authentication;
the origin of the evidence is not established. A compromised operator could
forge all input fields and artifact bytes. Independent reviewers must verify
the actual provider reports, cryptographic signatures and trust roots,
security/clinical approvals, and effective IAM controls before deployment.

No cloud clients, network requests, real patient data, or destructive
operations are used by this module.
