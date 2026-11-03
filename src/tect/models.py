from enum import Enum
from pydantic import BaseModel, Field


class Relation(str, Enum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"


class Evidence(BaseModel):
    id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    locator: str = Field(min_length=1, description="Stable citation, DOI, or document locator")
    excerpt: str = Field(min_length=1)
    relation: Relation
    verified: bool = False


class Claim(BaseModel):
    id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    evidence: list[Evidence] = Field(default_factory=list)


class Assessment(BaseModel):
    claim_id: str
    status: str
    reasons: list[str]
    supporting_ids: list[str]
    contradicting_ids: list[str]
    policy_version: str = "v0.1"
