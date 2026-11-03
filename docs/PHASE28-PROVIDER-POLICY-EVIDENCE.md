# Phase 28 — Independent provider-policy evidence assessment

This phase introduces a signed reviewer attestation over the **actual bytes**
of an IAM policy assessment report, not just self-reported action strings.

`sign_policy_assessment(report, account_id=..., approval_reference=...,
reviewer_key_id=..., assertions=..., private_key=...)` signs the exact
SHA-256 digest and length of the report, provider account ID, approval
reference, four explicit pass assertions, reviewer key ID and timestamp.

`verify_policy_assessment(envelope, report, trusted_public_keys,
expected_account_id=..., expected_approval_reference=...)` validates the
signature against independently trusted Ed25519 reviewer keys, verifies
the complete assertions and binds the evidence bytes to the expected
account and approval. Maximum report size: 2 MiB.

**Assurance boundary:** the code cannot establish that a provider generated
the supplied report, that a reviewer is genuinely independent, or that
effective IAM permissions match the claims. Use an approved provider policy
simulator, authenticated cloud audit logs, and separate reviewer-controlled
key custody. This is an offline cryptographic verification component;
no real cloud calls, permission probes, or destructive tests occur.
