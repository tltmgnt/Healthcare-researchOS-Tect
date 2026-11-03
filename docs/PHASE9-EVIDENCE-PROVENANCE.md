# Phase 9 — Evidence provenance snapshots

The `tect.provenance` module captures a content-addressed snapshot of evidence
references (ID, source, locator, excerpt and relation) associated with an
existing versioned claim. A stored SHA-256 digest detects accidental or
unauthorized local changes when checked against the current claim version.

```python
from tect.provenance import capture_provenance, verify_provenance

capture_provenance("claim-id", 1)
result = verify_provenance("claim-id", 1)
```

This is an **opt-in** snapshot; existing claim writes do not automatically
create provenance records. The provenance table is not currently part of the
signed audit chain, and an administrator who controls both the claim and
provenance database can rewrite both. For stronger assurance, future phases
should atomically capture provenance on claim writes and anchor its digest
inside externally signed audit events.

A locator, excerpt, or digest does **not** prove that a scientific publication
exists, that a quotation is accurate, or that the evidence supports a clinical
claim. No DOI resolution, publisher authentication, retrieval of primary
sources, medical evidence grading, or clinical validation is implemented.
