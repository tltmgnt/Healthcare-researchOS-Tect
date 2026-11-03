from fastapi import FastAPI, HTTPException
from .engine import assess
from .models import Assessment, Claim

app = FastAPI(title="ResearchOS | TECT", version="0.1.0")
_claims: dict[str, Claim] = {}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/claims", response_model=Claim, status_code=201)
def create_claim(claim: Claim) -> Claim:
    if claim.id in _claims:
        raise HTTPException(status_code=409, detail="Claim already exists")
    _claims[claim.id] = claim
    return claim


@app.get("/claims/{claim_id}", response_model=Claim)
def get_claim(claim_id: str) -> Claim:
    if claim_id not in _claims:
        raise HTTPException(status_code=404, detail="Claim not found")
    return _claims[claim_id]


@app.get("/claims/{claim_id}/assessment", response_model=Assessment)
def get_assessment(claim_id: str) -> Assessment:
    return assess(get_claim(claim_id))
