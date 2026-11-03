# Phase 33 — Reviewer trust registry and key lifecycle

This increment requires a caller-supplied **independently maintained**
registry entry for the Ed25519 reviewer key used to sign Phase 32
release evidence.

Each reviewer entry must have a public key, reviewer identity, explicit
allowed submitters, an exact scope of all nine release gates, timezone-aware
valid-from and valid-until dates, and a revocation flag. Verification
fails closed if any control is missing or the reviewer equals the submitter.

The registry gate then invokes Phase 32's cryptographic signature and
Phase 31's evidence-byte digest and freshness checks.

**Critical operational dependency:** a registry supplied by the same
operator as the release evidence does not prove independence. Store,
authenticate, version, and audit the trust registry through a separate
security authority; protect private keys in independent custody and
maintain a revocation and rotation procedure. No cloud operations,
clinical approval, or production release occurs in this module.
