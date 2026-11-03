# Phase 35 — Durable reviewer-registry anti-rollback floor

Phase 34 requires a trusted, independently pinned minimum registry
sequence. Phase 35 adds a SQLite-backed persistent floor store using
`BEGIN IMMEDIATE` to serialize verification and advancement.

- Trusted one-time `RegistryFloorStore.provision(path, initial_sequence=...)`
  uses exclusive file creation and 0600 file permissions.
- `read()` fails closed on missing/corrupt state.
- `compare_and_advance(expected_floor=..., new_sequence=...)`
  atomically rejects stale comparisons and decreases.
- `verify_release_with_durable_floor(...)` holds a write lock across
  signed-registry and evidence verification, advancing the floor only
  when all release evidence checks pass.

**Security limitation:** this SQLite file is NOT independently
tamper-proof. A filesystem administrator can replace it with an older
snapshot or alter the database, and backup restoration can reset the
floor. Deploy under a separate security authority with restricted
filesystem permissions, independently protected backups, monitored
changes and an external monotonic anchor before trusting it in
production. This code does not grant production or clinical approval.
