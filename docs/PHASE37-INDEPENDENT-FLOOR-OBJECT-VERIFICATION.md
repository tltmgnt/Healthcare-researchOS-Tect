# Phase 37 — Independent object-storage floor-anchor verification

Adds a **read-only**, version-pinned S3-compatible retrieval adapter for
Phase 36 signed reviewer-registry floor anchors. A caller must explicitly
opt in to a **non-production** exercise, provide an approval reference,
allowlisted bucket, 12-digit approved cloud account and exact object
version ID. The adapter checks STS caller account before S3 reads, caps
anchor bytes at 64 KiB, checks returned version ID, verifies Ed25519
signature against independently supplied authority keys and enforces an
independently pinned minimum sequence. Optional local-floor comparison
detects a restored local database.

**This is not a retention or custody certification.** The caller must
independently authenticate endpoint configuration and effective IAM
permissions, inspect provider Object Lock retention and deletion-denial
results, protect authority keys and keep the latest monotonic pin in a
separate security boundary. No write or delete operations are performed.
No real cloud call is made by the automated tests.
