# Phase 6 — Historical audit verification

`tect.historical_audit.verify_historical_signed_checkpoint` verifies an Ed25519
checkpoint against a historical **prefix** of the current event log. Unlike
Phase 5 exact-head verification, legitimate appended events do not invalidate
an older checkpoint.

It verifies the public-key signature using a trusted key registry, validates
the checkpoint checksum, scans the **entire current chain**, checks contiguous
sequence numbers, checks event hashes, and checks referenced claim payloads.
Then it compares the historical prefix head with the signed checkpoint.

```python
from tect.historical_audit import verify_historical_signed_checkpoint
result = verify_historical_signed_checkpoint(envelope, {"key-1": trusted_public_key})
```

## Trust and limitations

Keep the signed checkpoint outside the SQLite administrator's trust boundary.
The verifier's trusted public key must be provisioned independently.
A signed checkpoint anchors a prefix, not events that happened afterward.
The full chain scan is O(n) and requires a consistent database snapshot.
External immutable publication, trusted timestamps, key revocation services,
and evidence provenance are not yet implemented. The signature does not
establish clinical validity.
