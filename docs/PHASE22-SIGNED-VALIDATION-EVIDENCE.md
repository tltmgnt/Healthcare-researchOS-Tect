# Phase 22 — Signed validation evidence bundles

`tect.signed_validation_evidence.sign_validation_bundle(attestations,
private_key, key_id)` signs a complete six-control Phase 21 operator
checklist with an Ed25519 key. Signing refuses missing, failed or unexpected
controls. `verify_validation_bundle(bundle, trusted_public_keys)` checks
the exact schema, signature and complete checklist against a separately
trusted public key map.

The signed bundle is portable JSON and can be retained in independent
storage. Use a reviewer-controlled signing key; distribute trusted public
keys through an independently managed channel. Preserve referenced
evidence artifacts with their own digests and access logs.

**Limits:** a valid signature only shows that the designated key signed
the attestation text. It does not verify the existence, content, authenticity
or completeness of the external evidence referenced, prove Object Lock
enforcement, or certify production/clinical readiness. Live-provider tests
and independent review remain mandatory.
