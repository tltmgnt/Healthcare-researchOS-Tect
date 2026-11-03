# Phase 19 — Per-object version retention evidence

`tect.object_retention_evidence.inspect_anchor_retention(client, bucket, key,
version_id, minimum_remaining_days=365)` uses the read-only S3-compatible
`get_object_retention` operation. It requires an explicit object version,
**COMPLIANCE** mode and a timezone-aware retention expiry at least the
requested number of full days into the future.

It fails closed on missing version IDs, malformed timestamps, governance
mode, insufficient retention or provider access errors. It returns a
point-in-time report with the checked version and retention timestamp.

This complements Phase 18 bucket configuration inspection. It does not
prove that a provider enforces retention, that independent custody exists,
or that deletion is denied. Operators must retain the report outside the
application trust boundary and separately test real provider permissions,
deletion denial, restore, trusted key distribution and audit procedures.
