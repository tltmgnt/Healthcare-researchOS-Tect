# Phase 4 — Authenticated checkpoint prototype

`tect.signed_checkpoints` adds an HMAC-SHA256 envelope over the Phase 3
checkpoint. It authenticates the checkpoint **only to parties sharing the same
secret**. It is **not an asymmetric digital signature** and does not give
independent auditors non-repudiation: anyone who can verify can also forge.

## Example

```python
import secrets
from tect.signed_checkpoints import sign_checkpoint, verify_signed_checkpoint

# Example only. In production, obtain keys from a managed secret store.
key = secrets.token_bytes(32)
envelope = sign_checkpoint(key, "rotation-2026-11")
assert verify_signed_checkpoint(envelope, {"rotation-2026-11": key})["valid"]
```

Never commit, log, or put the key into the checkpoint. Keep authenticated
checkpoint copies in independently controlled, immutable storage. Maintain a
trusted key-ID registry and a documented rotation/revocation process.

This verifier compares against the **current exact audit head**, not a
historical prefix. Normal new events invalidate the match until a new checkpoint
is issued. No independent timestamp, public-key signature, external anchoring,
key-management service, or biomedical evidence provenance is implemented here.

Future work: Ed25519 signatures with independently held verification keys,
historical-prefix validation, anchored sequence numbers, and provenance links.
