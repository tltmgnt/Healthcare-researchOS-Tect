# Phase 45 — Signed CloudTrail key registry integrity

An independent Ed25519 authority signs a canonical JSON envelope for
the Phase 44 RSA key registry. Verification requires an explicitly
trusted authority public key, a positive minimum sequence floor,
bounded payload size, exact signed fields, and a valid signature.
Only then may the Phase 44 region, account, revocation, validity and
RSA fingerprint checks run.

This protects registry bytes against unauthorized edits **relative to
a correctly provisioned authority key**. It does not independently
prove that any registered RSA key belongs to AWS. The authority key
and minimum sequence are caller-provided; external retention and
rollback-resistant custody remain operational requirements.

Next priorities: independently authenticate AWS CloudTrail signing
keys, implement AWS-specific canonical digest signature validation,
and validate using real provider-generated digest/log fixtures.
Production authorization remains outstanding.
