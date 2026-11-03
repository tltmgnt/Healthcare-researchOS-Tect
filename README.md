# ResearchOS | TECT

Early-stage research assurance prototype. Deterministic assessments of evidence relationships **do not establish clinical correctness**.

## Quick start

```bash
python -m pip install -e ".[dev]"
export TECT_DB_PATH=tect.sqlite3
uvicorn tect.api:app --reload
pytest -q
```

Open http://127.0.0.1:8000/docs for the API.

## Implemented

- Typed claims and evidence with supports/contradicts relationships
- Conservative deterministic assessment policy
- SQLite-backed claim history; each revision creates a new version
- Optimistic concurrency using `expected_version`
- SHA-256 chained audit events, with endpoint to verify stored history
- REST endpoints to create/revise/read claims, list versions, assess, and verify the chain
- Synthetic tests and CI

## Example

```bash
curl -X POST http://localhost:8000/claims -H 'Content-Type: application/json' -d '{"id":"demo","text":"Synthetic example"}'
curl http://localhost:8000/claims/demo/versions
curl http://localhost:8000/audit/verify
```

## Security and scientific limitations

**Not production-ready. Never submit PHI or use for clinical decisions.**
No authentication, authorization, encryption at rest, or access controls. SQLite is local and single-instance; configure a protected database path and backups. The audit chain is *tamper-evident only relative to a trusted external anchor*: an administrator with write access could rewrite all records and hashes. Evidence `verified` is caller-supplied and **does not** establish provenance or scientific reliability. No source retrieval, independent provenance verification, formal verification, adversarial evaluation, or clinical validation is implemented.

Next: externally anchor audit heads, add access controls, provenance verification, schema migrations, and adversarial test suites.
