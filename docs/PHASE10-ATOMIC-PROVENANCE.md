# Phase 10 — Atomic evidence provenance binding

Every new claim revision now writes its versioned claim payload, evidence
provenance snapshot, and audit event in one SQLite transaction. New audit
events are tagged `claim.saved.provenance`; the existing event hash commits
to the claim payload, which contains the full evidence content.

Both the current-chain and historical-prefix verifiers require the
corresponding provenance snapshot for these new events. Deleting or changing
a snapshot makes verification fail. Legacy `claim.saved` events remain
readable and do not require backfilled provenance records.

This is an integrity and traceability mechanism, **not** a proof of external
source authenticity, evidence accuracy, or clinical validity. The provenance
table is locally controlled; the signed external checkpoint is needed to
detect coordinated rewriting of the local audit history. Existing Phase 9
manual snapshots remain supported.
