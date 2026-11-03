# Phase 12 — Auditable evidence verification observations

`tect.verification_records.record_doi_verification` captures the DOI resolver
status, method identifier, UTC observation timestamp, claim-version payload
hash, and the evidence ID in an append-only local SQLite hash chain.
`verify_doi_verification_log` checks sequence continuity, event hashes,
hash links, and the referenced claim version's payload.

```python
from tect.verification_records import record_doi_verification, verify_doi_verification_log
record = record_doi_verification("claim-id", 1, "evidence-id")
report = verify_doi_verification_log()
```

Repeated checks create distinct observations rather than overwriting history.
A network failure can be recorded as `metadata_unavailable`; it is not
interpreted as invalid scientific evidence.

**Security boundary:** This is a **separate local hash chain** and is not yet
included in the main signed audit checkpoint. A database administrator could
rewrite it and recompute hashes. Independent signing, external anchoring,
access controls for reading these observations, and integration with the main
audit chain remain future work. DOI metadata matches do not establish excerpt
accuracy, study quality, or clinical truth.
