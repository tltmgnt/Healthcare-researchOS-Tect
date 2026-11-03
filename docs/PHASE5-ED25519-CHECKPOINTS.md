# Phase 5 — Ed25519 independently verifiable checkpoints

This increment uses **Ed25519 asymmetric digital signatures** to separate
signing authority (private key) from verification authority (public key).
It adds the `cryptography` runtime dependency.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tect.ed25519_checkpoints import sign_checkpoint, verify_signed_checkpoint

# Example only: real signing keys must be loaded from secure key custody.
private_key = Ed25519PrivateKey.generate()
envelope = sign_checkpoint(private_key, "audit-key-1")
result = verify_signed_checkpoint(envelope, {"audit-key-1": private_key.public_key()})
assert result["valid"]
```

**Trust boundaries:** Distribute and pin public keys via a separately trusted
registry. A public key supplied alongside an untrusted manifest is not a trust
anchor. Keep private keys out of source control and application logs; use a
managed KMS/HSM for production signing. Define rotation and revocation policy.

**Limitations:** Verification compares against the current *exact* SQLite audit
head, so legitimate later events cause `head_mismatch`. External immutable
publication, trusted timestamps, historical-prefix verification, key registry
services, and biomedical source-evidence provenance are not yet implemented.
A signature authenticates the signer/key, not the clinical truth of a claim.
