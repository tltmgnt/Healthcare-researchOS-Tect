"""Fail-closed final release-gate assessment.

This module evaluates independently provided evidence references and
approvals. It cannot certify their authenticity or deploy anything.
"""
from datetime import datetime, timezone

SCHEMA = "tect.technical-release-gates.v1"
REQUIRED_GATES = (
    "engineering_ci_and_review",
    "independent_security_assessment",
    "live_provider_iam_validation",
    "live_object_lock_deletion_denial",
    "independent_storage_and_key_custody",
    "verified_backup_and_recovery_exercise",
    "privacy_and_data_governance_review",
    "clinical_use_and_regulatory_approval",
    "operational_monitoring_and_incident_response",
)


def evaluate_release_gates(gates: dict, *, assessed_at: datetime | None = None) -> dict:
    """Require explicit pass, independent approver and evidence per gate."""
    now = assessed_at if assessed_at is not None else datetime.now(timezone.utc)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Timezone-aware assessed_at required")
    if not isinstance(gates, dict):
        raise ValueError("Release gates must be a dictionary")
    results = {}
    for gate in REQUIRED_GATES:
        record = gates.get(gate)
        if not isinstance(record, dict):
            results[gate] = {"passed": False, "reason": "missing_gate"}
            continue
        passed = record.get("passed") is True
        evidence = record.get("evidence_reference")
        approver = record.get("independent_approver")
        approval_date = record.get("approved_at")
        accepted = (passed and isinstance(evidence, str) and bool(evidence.strip())
                    and isinstance(approver, str) and bool(approver.strip())
                    and isinstance(approval_date, str) and bool(approval_date.strip()))
        results[gate] = {"passed": accepted,
                         "reason": "attested" if accepted else "failed_or_incomplete"}
    unexpected = sorted(set(gates) - set(REQUIRED_GATES))
    ready = all(item["passed"] for item in results.values()) and not unexpected
    return {"schema": SCHEMA, "release_gates_attested": ready,
            "assessed_at": now.isoformat(),
            "passed_count": sum(item["passed"] for item in results.values()),
            "required_count": len(REQUIRED_GATES),
            "unexpected_gates": unexpected, "gates": results,
            "limitations": "Attestation completeness only; not authenticated evidence, external certification, deployment authorization or clinical safety proof"}
