from .models import Assessment, Claim, Relation


def assess(claim: Claim) -> Assessment:
    """Conservative deterministic policy; not a clinical truth judgment."""
    supports = [e.id for e in claim.evidence if e.verified and e.relation == Relation.SUPPORTS]
    contradicts = [e.id for e in claim.evidence if e.verified and e.relation == Relation.CONTRADICTS]
    reasons: list[str] = []
    if contradicts:
        status = "contested"
        reasons.append("Verified contradicting evidence exists")
    elif not supports:
        status = "insufficient_evidence"
        reasons.append("No verified supporting evidence")
    else:
        status = "supported"
        reasons.append("At least one verified supporting evidence item; independent review still required")
    if any(not e.verified for e in claim.evidence):
        reasons.append("Unverified evidence excluded from assessment")
    return Assessment(
        claim_id=claim.id, status=status, reasons=reasons,
        supporting_ids=supports, contradicting_ids=contradicts,
    )
