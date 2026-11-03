# Phase 16 — Portable signed composite anchor files

Use `tect.composite_anchor_export.export_composite_anchor(path, private_key, key_id)`
to write an Ed25519-signed checkpoint of **both** claim and DOI verification
histories to a new, exclusive file. Existing paths cannot be overwritten;
on POSIX, the file is created with owner-only permissions. Writes are flushed
and fsynced, and verification reads are size-bounded.

Use `verify_composite_anchor_file(path, trusted_public_keys)` to validate
the independently retrieved file against the current local histories.
Historical prefixes are supported, including legitimate later events.

**Custody is not automated.** Export the resulting file to a separately
administered immutable location and independently distribute trusted public
keys. A local file on the application host is not an independent anchor.
Operational durability of the containing directory and external retention
policies are not guaranteed by this helper. This is bibliographic/audit
assurance, not clinical evidence validation.
