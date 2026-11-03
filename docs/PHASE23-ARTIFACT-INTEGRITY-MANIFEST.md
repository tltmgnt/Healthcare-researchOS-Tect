# Phase 23 — Signed evidence artifact integrity manifest

`tect.validation_artifact_manifest.sign_artifact_manifest(attestations,
artifacts, private_key, key_id)` takes the complete Phase 21 checklist and
a mapping from each of its six control IDs to **the actual evidence bytes**.
It produces a signed Phase 22 validation bundle plus a separately signed
manifest binding each evidence reference to its SHA-256 digest and byte count.

`verify_artifact_manifest(manifest, artifacts, trusted_public_keys)`
requires independently obtained trusted public keys and **all six artifact
byte strings**. It verifies both Ed25519 signatures, exact control/reference
binding, file sizes and SHA-256 digests. Missing, altered, empty or oversized
artifacts fail closed (16 MiB per artifact maximum).

Example: `artifacts = {"denied_deletion_test": open_report_bytes, ...}`
with an entry for every control in `REQUIRED_CONTROLS`. Retrieve the bytes
from an independently administered evidence repository; this module does
not fetch URLs or authenticate remote servers.

**Assurance boundary:** a valid result proves the supplied bytes match
those signed by the reviewer-controlled key. It does not prove the reports
are truthful, from the stated cloud provider, or that retention and
deletion-denial controls operate correctly. External storage, signing-key
custody, security review and live validation remain required.
