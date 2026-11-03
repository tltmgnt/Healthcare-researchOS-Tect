# Phase 18 — Read-only Object Lock assurance preflight

`tect.object_lock_assurance.inspect_anchor_bucket(client, bucket,
minimum_retention_days=365)` inspects a configured S3-compatible bucket
through `get_bucket_versioning` and `get_object_lock_configuration`.

The preflight requires versioning **Enabled**, Object Lock **Enabled**, a
default retention rule in **COMPLIANCE** mode, and a minimum duration.
Missing settings, governance mode, short retention, or API errors fail closed.

This does not create or modify cloud resources, grant permissions, or prove
that an individual anchor version has retained legal holds/retention.
An operator must additionally verify per-object retention with the actual
provider, validate independent account/key custody, test denied deletion,
and demonstrate retrieval during recovery. This is a configuration snapshot,
not a certification of immutability or clinical integrity.
