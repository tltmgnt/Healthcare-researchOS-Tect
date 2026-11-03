# Phase 34 — Signed reviewer registry and anti-rollback

The reviewer trust registry introduced in Phase 33 is now a portable
Ed25519-signed JSON snapshot. Each entry includes reviewer public key
bytes, identity, allowed submitters, exact gate scope, validity dates and
revocation status. Only an independently trusted **registry authority**
can issue an accepted registry snapshot.

`verify_signed_trust_registry` verifies the authority signature and
requires a caller-supplied `minimum_sequence` at least as high as the
last independently accepted registry sequence. Older snapshots fail
closed. `verify_release_with_signed_registry` gates Phase 33's signed
release-evidence verification on this trusted registry.

**Important:** the minimum sequence and authority public keys MUST be
stored outside the control of the release submitter and registry publisher
(e.g., separate security account with protected, durable monotonic state).
A caller who can reset the floor can bypass rollback detection. This
implementation does not itself provide monotonic storage, prove custody,
validate a real-world reviewer, or authorize a production release.

No live cloud access, patient data or destructive actions occur.
