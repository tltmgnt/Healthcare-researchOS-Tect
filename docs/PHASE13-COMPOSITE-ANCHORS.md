# Phase 13 — Signed composite audit anchors

`tect.composite_anchors.sign_composite_anchor` signs the head and event count
of **both** the claim audit chain and the DOI verification-observation chain
in one Ed25519 envelope. `verify_composite_anchor` checks the signature
against an independently provisioned public key, validates the complete
current chains, and compares their historical prefixes. Legitimate appended
events do not invalidate an older anchor.

```python
from tect.composite_anchors import sign_composite_anchor, verify_composite_anchor
anchor = sign_composite_anchor(private_key, "audit-key")
report = verify_composite_anchor(anchor, {"audit-key": trusted_public_key})
```

## Security and operational limitations

This creates a new composite anchor format. Legacy checkpoint envelopes do
**not** include DOI verification events and remain unchanged. Operators must
retain the composite envelope outside the database administrator's trust
boundary, ideally in independently managed immutable storage. Neither
external publication nor independent custody is performed automatically.

The two chains are read separately, not from one cross-table snapshot; a
concurrent writer could change one chain between reads. For stronger
assurance, capture both chain heads in one SQLite read transaction.
Verification is a local integrity check against a trusted external anchor,
not proof that DOI metadata or clinical conclusions are correct.
