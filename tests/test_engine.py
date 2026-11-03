from tect.engine import assess
from tect.models import Claim, Evidence, Relation


def evidence(id: str, relation: Relation, verified: bool = True) -> Evidence:
    return Evidence(id=id, source="synthetic", locator=f"synthetic:{id}",
                    excerpt="Fixture only", relation=relation, verified=verified)


def test_no_evidence_is_insufficient():
    assert assess(Claim(id="c1", text="Example")).status == "insufficient_evidence"


def test_verified_support():
    claim = Claim(id="c1", text="Example", evidence=[evidence("e1", Relation.SUPPORTS)])
    assert assess(claim).status == "supported"


def test_contradiction_takes_precedence():
    claim = Claim(id="c1", text="Example", evidence=[
        evidence("e1", Relation.SUPPORTS), evidence("e2", Relation.CONTRADICTS)])
    assert assess(claim).status == "contested"


def test_unverified_evidence_is_excluded():
    claim = Claim(id="c1", text="Example", evidence=[evidence("e1", Relation.SUPPORTS, False)])
    assert assess(claim).status == "insufficient_evidence"
