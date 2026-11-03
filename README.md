# ResearchOS | TECT

Early implementation of an AI-native research assurance framework. This prototype evaluates evidence relationships **without claiming clinical correctness**.

## Quick start

```bash
python -m pip install -e ".[dev]"
uvicorn tect.api:app --reload
pytest
```

Open http://127.0.0.1:8000/docs for interactive API documentation.

## Phase 1 scope

- Typed claims and evidence, with explicit supporting/contradicting edges
- Conservative deterministic assessment policy
- REST endpoints for creating, reading, and assessing claims
- Synthetic unit-test fixtures

**Limitations:** Storage is in memory and resets on restart. Evidence verification is supplied by the caller and is **not** independently checked. There is no authentication, durable audit log, provenance verification, clinical validation, or PHI handling. Do not use with patient data or for clinical decisions.

## Next steps

Persist versioned claims and evidence in a database, add immutable audit events, enforce authentication and access controls, implement provenance verification, and add adversarial evaluation suites before considering production deployment.
