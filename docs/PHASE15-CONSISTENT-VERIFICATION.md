# Phase 15 — Consistent composite-anchor verification

Composite Ed25519 anchor verification now checks both historical claim
and DOI-verification log prefixes in **one explicit SQLite read transaction**.
This prevents a concurrent writer from causing verification to compare
chain states captured at different moments.

`verify_audit_prefix` and the internal DOI prefix verifier accept an optional
existing SQLite connection while retaining their standalone behavior.
Cryptographic signature verification happens before the read transaction.

The verifier still checks the full current chains before accepting a
historical prefix, so appended valid events remain supported.

**Remaining production gates:** independent trusted public-key distribution,
externally held immutable composite anchors, deployment access controls,
operational restore tests, and domain/clinical validation.
