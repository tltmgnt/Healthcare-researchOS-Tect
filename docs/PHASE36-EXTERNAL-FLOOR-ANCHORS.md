# Phase 36 — External registry-floor anchors

This increment creates a portable Ed25519-signed checkpoint of the
Phase 35 persistent reviewer-registry minimum sequence.

`sign_floor_anchor(store, authority_key_id=..., private_key=..., created_at=...)`
signs the current floor. An independent security authority should
retain this signed anchor in immutable, versioned storage.

`verify_floor_anchor(..., independently_pinned_sequence=..., checked_at=...)`
requires a trusted authority signature and rejects anchors below a
separately maintained sequence floor.

`verify_local_floor_against_anchor(...)` additionally rejects local
floor state below the signed anchor. This detects a local database
restore when the independent anchor remains available.

**Trust boundary:** this implementation does not upload anchors, prove
Object Lock enforcement, or maintain the independent pinned sequence.
A privileged operator who can replace both the local floor and the
anchor or reset the independent pin can defeat rollback detection.
Deploy independent custody, immutability, and retention controls before
treating this as production assurance. No clinical approval or
production authorization is granted.
