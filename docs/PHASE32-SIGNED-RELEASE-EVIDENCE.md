# Phase 32 — Signed release evidence

Production Assurance Phase 32 signs the **complete release-gate
attestation and evidence-digest metadata** using Ed25519.

`sign_release_evidence` accepts reviewer-held private key material and
produces a canonical signed envelope containing all nine gate records,
submitter ID, reviewer key ID, assessment timestamp and freshness policy.

`verify_signed_release_evidence` checks the signature against an
independently configured trusted reviewer public key, requires an exact
submitter ID, rejects future or older-than-24-hour signed assessments,
then verifies the **actual evidence bytes** using Phase 31's digest,
freshness and self-approval checks. A valid signature does **not** imply
`release_evidence_ready` when any artifact is missing or altered.

**Trust boundary:** the signing key must be controlled by a genuine
independent reviewer. This code does not validate reviewer identity,
organizational independence, the provenance of cloud reports, or the
legitimacy of clinical approvals. The signature is an integrity mechanism,
not a certificate of production readiness. No cloud operations occur.
