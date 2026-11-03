# Phase 14 — Consistent cross-chain snapshot at signing

Composite anchor signing now validates the claim and DOI-verification chains
through the **same SQLite connection and explicit read transaction**.
SQLite pins a consistent snapshot on the first read, preventing concurrent
writes from creating a mixed-time pair of chain heads during signing.
Both chain verifiers still work without a supplied connection.

The transaction is rolled back after both heads are collected, and the
Ed25519 envelope is signed afterward. A concurrent writer can append new
events after the snapshot; the historical-prefix verifier continues to
accept legitimate append-only history.

**Remaining production gates:** the existing composite verification path
still reads chains in separate transactions; external immutable publication
and key custody must be configured and tested independently. No deployment
or clinical validation is implied by this change.
