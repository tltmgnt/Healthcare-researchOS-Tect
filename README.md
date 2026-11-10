# ResearchOS | TECT

Early-stage research assurance prototype. Deterministic assessments of evidence relationships **do not establish clinical correctness**.

## Quick start

Set `TECT_API_KEYS_JSON` before calling protected API routes; see [security setup](docs/PHASE2-SECURITY.md).

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
Phase 2 adds static bearer-token authentication and role-based endpoint authorization; encryption at rest, per-claim access controls, and production identity management remain absent. SQLite is local and single-instance; configure a protected database path and backups. The audit chain is *tamper-evident only relative to a trusted external anchor*: an administrator with write access could rewrite all records and hashes. Evidence `verified` is caller-supplied and **does not** establish provenance or scientific reliability. No source retrieval, independent provenance verification, formal verification, adversarial evaluation, or clinical validation is implemented.

See [Phase 2 security guide](docs/PHASE2-SECURITY.md) for configuration and role permissions. Next: externally anchor audit heads, implement per-claim access controls and production identity management, provenance verification, schema migrations, and adversarial test suites.

## ResearchOS / TECT concept integration

The [ResearchOS / Topological Epistemic Control Theory technical concept paper](docs/researchos/TECT_WHITE_PAPER.md) proposes an epistemic control and assurance infrastructure for AI-generated knowledge. Read the [repository integration status](docs/researchos/INTEGRATION.md) and [machine-readable scope](docs/researchos/integration.json) for the boundary between the concept and implemented capabilities. Performance targets are research objectives, not achieved results. This documentation addition does not implement the complete ResearchOS architecture or change operational authority.

## Portfolio implementation boundary

See [current implementation and shared-core integration](docs/portfolio/INTEGRATION.md) and [machine-readable status](docs/portfolio/STATUS.json). Independent empirical reproduction and real-provider acceptance remain separate from software checks.

**∞**

## Topology compatibility and curriculum

See the [repository-specific v2 curriculum](docs/portfolio/TOPOLOGY_CURRICULUM_V2.md) for the minimum useful mathematics, six-criterion compatibility scorecard, source-linked exercises and adoption boundaries.
