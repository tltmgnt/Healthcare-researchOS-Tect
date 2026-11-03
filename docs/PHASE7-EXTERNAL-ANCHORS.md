# Phase 7 — Portable external audit anchor export

The `tect.anchor_export` module creates a portable Ed25519-signed checkpoint
file and verifies a retrieved checkpoint against the historical prefix of the
current SQLite audit chain.

```python
from tect.anchor_export import export_signed_anchor, verify_anchor_file

# private_key is loaded securely; trusted_public_key comes from a pinned registry.
export_signed_anchor("/secure-staging/checkpoint-001.json", private_key, "audit-key-1")
result = verify_anchor_file("/secure-staging/checkpoint-001.json", {"audit-key-1": trusted_public_key})
```

The export uses exclusive file creation (no overwrite), owner-only permissions
on POSIX, and fsync. **This does not implement external anchoring by itself.**
An operator must transfer the checkpoint to a separately administered immutable
or append-only storage service and retain independent proof of custody.
Do not put signing private keys in the exported file or source repository.
Verify keys from a trusted, independently maintained registry.

## Remaining gaps

No cloud storage integration, remote write confirmation, trusted timestamp,
key revocation service, provenance for scientific evidence, or independent
clinical validation. File export alone does not defend against a privileged
attacker who controls both the database and the exported files.
