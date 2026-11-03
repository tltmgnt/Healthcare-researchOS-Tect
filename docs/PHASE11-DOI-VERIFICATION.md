# Phase 11 — Independent DOI metadata checks

`tect.doi_verification.verify_evidence_doi` resolves DOI references from a
specific stored claim version using the public Crossref works API. It checks
that the returned DOI matches the requested DOI and reports bibliographic
title, publisher and work type where available.

```python
from tect.doi_verification import verify_evidence_doi
result = verify_evidence_doi("claim-id", 1, "evidence-id")
```

The default resolver uses HTTPS, a fixed Crossref hostname, redirect rejection,
a five-second timeout and a response-size limit. Tests inject a local resolver
and do not make network requests. DOI metadata is not available for all
registrants through Crossref; an unavailable response must not be treated as
proof that the DOI is invalid.

**Assurance boundary:** `metadata_matched` only confirms a bibliographic
DOI match at query time. It does not validate the excerpt, study design,
clinical accuracy, retractions, conflicts of interest or whether the cited
work supports the claim. The check is not persisted in the audit chain and
does not change the `Evidence.verified` flag.
