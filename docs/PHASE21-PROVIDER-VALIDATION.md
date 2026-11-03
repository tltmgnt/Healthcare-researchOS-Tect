# Phase 21 — Live-provider validation readiness

This phase adds a **non-destructive, offline** evidence checklist for
operational assurance. Use
`tect.provider_validation.evaluate_provider_validation(attestations)`
with operator-supplied evidence references and independent reviewer names.

Six required controls:

1. Independently administered anchor storage account.
2. Real Object Lock compliance retention evidence.
3. Authorized **denied deletion** test against a disposable test object.
4. Independently controlled signing keys and trusted public-key distribution.
5. Restored-anchor retrieval and cryptographic/history verification.
6. Credential rotation and revocation exercises.

Every control requires an explicit `passed: true`, nonempty
`evidence_reference`, `reviewer`, and `reviewed_at`. Missing or failed
controls yield `ready: false`. Store actual reports and signed evidence in
a separately controlled system; do not put secrets in evidence references.

**Safety:** Never test deletion against production anchors. Use a disposable
object, approved test window, and provider-authorized procedures.
The software does not call cloud APIs, create resources, delete objects, or
authenticate evidence references. A green checklist means that all fields
were attested, **not** that controls have been independently verified.
Clinical and security review remain separate deployment gates.
