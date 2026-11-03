# Phase 25 — Controlled read-only provider integration validation

The opt-in `run_readonly_provider_validation` function coordinates Phase 20
anchor recovery assurance and Phase 24 signed evidence retrieval. It requires:

- `enabled=True` as an explicit opt-in.
- `environment="non-production"` and a nonempty approval reference.
- Explicit anchor object version and expected digest.
- Explicit evidence object-version locations and independently trusted public keys.
- An injected, separately provisioned **read-only** S3-compatible client.

Without opt-in, non-production designation or approval, the function
returns a fail-closed result **without calling the provider**. The output
includes the approval reference, timestamp, check results and limitations,
suitable for retention in a separately controlled audit system.

**Operator safety requirements:** use dedicated test credentials restricted
to read/list/configuration inspection, approved test buckets, a time-bounded
change ticket and out-of-band evidence capture. The environment label is
caller-provided and does **not** technically prove that a bucket is
non-production. Enforce account/bucket restrictions in IAM and organizational
policy before invoking the function. This code does not create, mutate or
delete cloud objects and **does not perform deletion-denial tests**.

Unit tests use mocks only. No real-provider tests, independent custody
validation, or production/clinical certification are included.
