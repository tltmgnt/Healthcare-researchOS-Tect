# Phase 39 — Signed independent-custody and deletion-denial evidence

Adds an Ed25519-signed assessment envelope binding **six required controls**
to exact SHA-256 digests of supplied evidence bytes: independent storage
account, independent key custody, version-pinned anchor retrieval,
COMPLIANCE retention verification, protected-version deletion denial,
and credential revocation exercise.

The verifier checks a separately configured trusted assessor key,
assessor/operator separation, assessment freshness (90 days by default),
exact cloud account, bucket, key and object version, and the complete
six-control artifact set. Missing, failed, stale, mismatched or
tampered records fail closed. The code performs **no provider mutations**.

**Critical limitation:** this is authenticated attestation of supplied
evidence, not independent proof that provider deletion was actually
denied. The trusted assessor key must be provisioned and governed
independently; artifact provenance, cloud audit logs, provider identity
and external security signoff must be verified in real-world exercises.
Never attempt deletion tests on production assets without a separately
approved disposable target. Production authorization remains pending.
