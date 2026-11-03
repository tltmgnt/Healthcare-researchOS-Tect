# Phase 29 — Combined recovery validation evidence report

`generate_recovery_validation_report(storage_client, identity_client,
policy_envelope=..., policy_report=..., trusted_reviewer_keys=...,
approved_account_id=..., approved_buckets=..., **validation_args)`
requires an explicitly approved non-production invocation.

The report verifies a Phase 28 Ed25519-signed reviewer IAM assessment
against exact evidence bytes, account ID and approval reference **before**
calling any cloud client. If valid, it delegates to the Phase 26
approved-account/bucket gate and Phase 25 read-only provider assurance
runner, which checks Phase 20 anchor recovery and Phase 24 evidence
artifact retrieval.

Results are fail-closed and contain the timestamp, approval, target
account, individual check outcomes, details and limitations.

**Limits:** the report is an aggregate of signed operator assertions
and read-only provider responses. It does not establish provider-issued
report authenticity, effective IAM restrictions, independent custody,
deletion denial, clinical safety, or deployment readiness. Test only
against separately approved non-production resources with enforced
read-only IAM and independent evidence retention.
