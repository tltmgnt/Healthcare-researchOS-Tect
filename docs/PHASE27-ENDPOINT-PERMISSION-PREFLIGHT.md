# Phase 27 — Endpoint and credential permission preflight

`inspect_readonly_configuration` checks a caller-supplied endpoint URL
against an independently approved exact HTTPS endpoint allowlist and
requires declared read actions, explicit deny declarations for known
mutating actions, and no wildcard/mutating allows.

**Security boundary:** this is a **static declaration preflight**, not
verification of effective IAM permissions, TLS certificate trust, session
policies, bucket policies, permission boundaries, or provider authenticity.
It must not be interpreted as proving read-only credentials. Enforce
read-only permissions at the cloud IAM level, validate effective permissions
with the provider's policy simulator and independent reviewer, and restrict
the network endpoint before any live Phase 26 run.

The module makes no network calls and does not alter cloud resources.
Its explicit deny list is intentionally conservative and is not a complete
model of all possible S3 mutations or policy interactions.
