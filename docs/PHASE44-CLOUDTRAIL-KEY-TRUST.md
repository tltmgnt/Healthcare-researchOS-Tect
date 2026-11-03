# Phase 44 — Trusted CloudTrail signing-key controls

Adds offline RSA SubjectPublicKeyInfo SHA-256 fingerprint pinning, exact
key ID, region/account scopes, key validity intervals, explicit
revocation, required provenance references and a monotonic registry
sequence floor. RSA signature verification is gated on these checks.

**Trust limitation:** the key registry and its monotonic floor are
caller-supplied; a provenance reference is only a label. A successful
result does not establish AWS ownership of the public key or verify
AWS CloudTrail's canonical signed message. A separately signed and
independently retained key registry, AWS-authenticated key discovery,
AWS-specific signature-message reconstruction and live CloudTrail
validation are required before provider-origin assurance can pass.
No provider API calls or destructive operations are performed.
