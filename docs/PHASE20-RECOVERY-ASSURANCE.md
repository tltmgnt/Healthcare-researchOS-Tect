# Phase 20 — Composite anchor recovery assurance audit

`tect.recovery_assurance.audit_composite_anchor_recovery` performs three
read-only checks for a specified external object **version**:

1. Bucket versioning, Object Lock and COMPLIANCE-mode default retention.
2. Per-object-version COMPLIANCE retention through the requested horizon.
3. Retrieved object SHA-256 digest, Ed25519 signature, and both local audit
   histories, including valid historical prefixes.

It returns a structured report with check statuses and details, and only
reports `ready: true` when every check passes. Pass an independently
retained `expected_sha256`, a trusted public-key map, and an explicit
`version_id`. The `now` override supports deterministic offline tests.

This is **not** a certification that cloud Object Lock enforcement works or
that anchor storage is independently controlled. Operators must validate
real provider deletion denial, separate account custody, key management,
restoration, and ongoing monitoring. All tests use a simulated provider;
no cloud configuration or data is modified by the audit.
