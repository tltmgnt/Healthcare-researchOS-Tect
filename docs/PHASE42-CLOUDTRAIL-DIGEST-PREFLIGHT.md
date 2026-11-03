# Phase 42 — CloudTrail digest cryptographic preflight

Offline preflight verifies:
- SHA-256 digest pinning of supplied CloudTrail digest bytes.
- RSA PKCS#1 v1.5 SHA-256 signature over an explicitly supplied message,
  using a separately trusted RSA public key (minimum 2048 bits).
- SHA-256 checks for the exact expected set of log files listed by a
  `logFiles` manifest, with bounded bytes and strict path matching.

**NOT complete AWS CloudTrail signature validation:** the code does not
reconstruct AWS's canonical signed message, independently authenticate
AWS region/time-scoped public keys, verify `previousDigestHashValue`
continuity, or retrieve provider-owned logs. A signature on an arbitrary
caller-supplied message is not proof that AWS signed a digest. These
missing controls must be implemented and independently validated before
claiming provider-origin authenticity or production readiness.
