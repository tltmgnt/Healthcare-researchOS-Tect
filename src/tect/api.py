from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from .auth import Principal, require
from .engine import assess
from .models import Assessment, Claim
from .storage import claim_versions, load_claim, save_claim, verify_audit_chain

app = FastAPI(title="ResearchOS | TECT", version="0.3.0")


class ClaimRevision(BaseModel):
    claim: Claim
    expected_version: int = Field(ge=1)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/claims", response_model=Claim, status_code=201)
def create_claim(claim: Claim, principal: Principal = Depends(require("write"))) -> Claim:
    try:
        save_claim(claim, expected_version=0)
    except ValueError:
        raise HTTPException(status_code=409, detail="Claim already exists")
    return claim


@app.put("/claims/{claim_id}", response_model=Claim)
def revise_claim(claim_id: str, revision: ClaimRevision,
                 principal: Principal = Depends(require("write"))) -> Claim:
    if revision.claim.id != claim_id:
        raise HTTPException(status_code=422, detail="Claim ID mismatch")
    if load_claim(claim_id) is None:
        raise HTTPException(status_code=404, detail="Claim not found")
    try:
        save_claim(revision.claim, expected_version=revision.expected_version)
    except ValueError:
        raise HTTPException(status_code=409, detail="Version conflict")
    return revision.claim


@app.get("/claims/{claim_id}", response_model=Claim)
def get_claim(claim_id: str, version: int | None = None,
              principal: Principal = Depends(require("read"))) -> Claim:
    if version is not None and version < 1:
        raise HTTPException(status_code=422, detail="Version must be positive")
    claim = load_claim(claim_id, version)
    if claim is None:
        raise HTTPException(status_code=404, detail="Claim not found")
    return claim


@app.get("/claims/{claim_id}/versions", response_model=list[int])
def get_versions(claim_id: str, principal: Principal = Depends(require("read"))) -> list[int]:
    versions = claim_versions(claim_id)
    if not versions:
        raise HTTPException(status_code=404, detail="Claim not found")
    return versions


@app.get("/claims/{claim_id}/assessment", response_model=Assessment)
def get_assessment(claim_id: str, version: int | None = None,
                   principal: Principal = Depends(require("read"))) -> Assessment:
    return assess(get_claim(claim_id, version, principal))


@app.get("/audit/verify")
def audit_verify(principal: Principal = Depends(require("audit"))) -> dict:
    return verify_audit_chain()
