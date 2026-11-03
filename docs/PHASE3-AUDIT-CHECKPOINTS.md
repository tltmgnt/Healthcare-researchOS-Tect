# Phase 3 — Audit checkpoint prototype

This phase adds exportable audit head manifests and exact-head verification.

## Usage

```python
from tect.checkpoints import write_checkpoint, verify_checkpoint
import json

write_checkpoint("/secure-external-store/checkpoint.json")
with open("/secure-external-store/checkpoint.json") as f:
    result = verify_checkpoint(json.load(f))
print(result)
```

**Critical trust boundary:** The checkpoint must be retained by a separately administered,
append-only or immutable store. A manifest saved beside the SQLite database is **not**
an independent trust anchor. Its SHA-256 checksum is not a digital signature and does
not authenticate the publisher. Verify the checkpoint's origin and custody out of band.

The verifier checks the current exact audit head. Any new legitimate event causes
a head mismatch; export a new externally retained checkpoint after reviewing those events.
The verifier does not yet verify a checkpoint against a historical prefix of an extended
ledger, and does not prevent a privileged attacker from rewriting both the database and
a checkpoint under their control.

Further work: independently signed anchors, trusted timestamping, immutable storage,
historical-prefix verification, event sequence-gap detection, and source-evidence provenance.
No healthcare clinical safety or compliance certification is claimed.
