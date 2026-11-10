# Topology compatibility and curriculum v2 — Healthcare-researchOS-Tect

Version 2 adapts the explicit-molecular-graph teaching pattern to this repository's actual role. This is documentation and a learning/decision framework; it introduces no mathematical engine, runtime dependency or operational permission.

## Repository decision

| Question | Repository-specific answer |
| --- | --- |
| Architectural role | application infrastructure |
| Minimum useful mathematics | Typed evidence graphs and versioned event histories |
| Relationships to preserve | Supports/contradicts relations, claim versions and audit order |
| Concrete operation / capstone | Revise a synthetic claim with an expected version and explain why a stale writer must be rejected |
| Necessity and scope boundary | Hash chains do not authenticate evidence or prevent an administrator from rewriting history |

The decision is a source-based recommendation, not measured proof that a new specialty improves this repository. Start with the existing implementation and compare any proposed abstraction against a simpler alternative.

## Six-criterion compatibility scorecard

Complete one scorecard per proposed candidate and per concrete operation. Leave unmeasured entries unknown. Scores are human judgments from 0 (no fit) to 5 (strong evidenced fit); unknown is not zero. Do not sum an incomplete card. A total out of 30 is a heuristic, not adoption approval, and feasibility or necessity can veto a high total.

| Criterion | Score | Required evidence |
| --- | --- | --- |
| Structural compatibility | Not yet scored | Map the repository objects and the relationships above without losing direction, labels, units or missingness. |
| Transformation support | Not yet scored | Demonstrate the capstone operation on accepted and rejected inputs. |
| Invariant preservation | Not yet scored | State the property preserved and supply a counterexample or perturbation. |
| Computational feasibility | Not yet scored | Measure size, time and memory on bounded fixtures; record limits. |
| Integration compatibility | Not yet scored | Verify existing schemas, APIs and neighboring contracts remain compatible. |
| Mathematical necessity | Not yet scored | Compare with typed evidence graphs and versioned event histories and explain the additional capability, if any. |

## Curriculum

Prerequisites: basic programming, sets, functions and graph vocabulary. Work in six competency-gated sessions, approximately 60–90 minutes each; empirical evaluation is a separate research activity.

| Session | Learning objective | Exercise | Completion evidence |
| --- | --- | --- | --- |
| 1. Model | Identify supports/contradicts relations, claim versions and audit order. | Draw a minimal valid example and one excluded relationship. | Annotated object/relation inventory with explicit assumptions. |
| 2. Contract | Distinguish schema validity from substantive correctness. | Trace validation and propose malformed, missing and boundary inputs. | Input-to-rejection table grounded in current source. |
| 3. Operation | Explain typed evidence graphs and versioned event histories. | Revise a synthetic claim with an expected version and explain why a stale writer must be rejected. | Hand trace compared with existing software, or a clearly labeled specification when no runtime exists. |
| 4. Preservation | State what a transformation must preserve. | Rename identifiers, reorder records, then alter one meaningful relation; predict each effect under the actual contract. | Separate invariant, expected change and unsupported transformation. |
| 5. Comparison | Justify mathematical necessity and cost. | Complete the six-criterion card for the existing approach and one proposed alternative; record unknowns honestly. | Evidence-backed recommendation with baseline and explicit veto conditions. |
| 6. Reproduction | Communicate the bounded result. | Reproduce the capstone using existing offline fixtures and record software version, inputs, outputs and limitations. | Reviewable notebook or report distinguishing computation, replay, independent evaluation and authorization. |

## Source-linked reading laboratory

The table is a guided selection of source lines, not an assertion that the whole repository is covered. Line numbers refer to the inspected source blob `bc4d9d974d6f1ac3d5fbbf5081f1b1caf4aee220` in [src/tect/models.py](../../src/tect/models.py). Recheck anchors after source changes.

| Line | Statement | Learning check |
| --- | --- | --- |
| [1](../../src/tect/models.py#L1) | `from enum import Enum` | Identify the dependency and explain which operation needs it. |
| [2](../../src/tect/models.py#L2) | `from pydantic import BaseModel, Field` | Identify the dependency and explain which operation needs it. |
| [5](../../src/tect/models.py#L5) | `class Relation(str, Enum):` | State the input/output contract and trace one normal and one failing case. |
| [6](../../src/tect/models.py#L6) | `SUPPORTS = "supports"` | Explain the statement, track its state change and predict its effect on the worked example. |
| [7](../../src/tect/models.py#L7) | `CONTRADICTS = "contradicts"` | Explain the statement, track its state change and predict its effect on the worked example. |
| [10](../../src/tect/models.py#L10) | `class Evidence(BaseModel):` | State the input/output contract and trace one normal and one failing case. |
| [11](../../src/tect/models.py#L11) | `id: str = Field(min_length=1)` | Explain the statement, track its state change and predict its effect on the worked example. |
| [12](../../src/tect/models.py#L12) | `source: str = Field(min_length=1)` | Explain the statement, track its state change and predict its effect on the worked example. |
| [13](../../src/tect/models.py#L13) | `locator: str = Field(min_length=1, description="Stable citation, DOI, or document locator")` | Explain the statement, track its state change and predict its effect on the worked example. |
| [14](../../src/tect/models.py#L14) | `excerpt: str = Field(min_length=1)` | Explain the statement, track its state change and predict its effect on the worked example. |
| [15](../../src/tect/models.py#L15) | `relation: Relation` | Explain the statement, track its state change and predict its effect on the worked example. |
| [16](../../src/tect/models.py#L16) | `verified: bool = False` | Explain the statement, track its state change and predict its effect on the worked example. |
| [19](../../src/tect/models.py#L19) | `class Claim(BaseModel):` | State the input/output contract and trace one normal and one failing case. |
| [20](../../src/tect/models.py#L20) | `id: str = Field(min_length=1)` | Explain the statement, track its state change and predict its effect on the worked example. |
| [21](../../src/tect/models.py#L21) | `text: str = Field(min_length=1)` | Explain the statement, track its state change and predict its effect on the worked example. |
| [22](../../src/tect/models.py#L22) | `evidence: list[Evidence] = Field(default_factory=list)` | Explain the statement, track its state change and predict its effect on the worked example. |
| [25](../../src/tect/models.py#L25) | `class Assessment(BaseModel):` | State the input/output contract and trace one normal and one failing case. |
| [26](../../src/tect/models.py#L26) | `claim_id: str` | Explain the statement, track its state change and predict its effect on the worked example. |
| [27](../../src/tect/models.py#L27) | `status: str` | Explain the statement, track its state change and predict its effect on the worked example. |
| [28](../../src/tect/models.py#L28) | `reasons: list[str]` | Explain the statement, track its state change and predict its effect on the worked example. |
| [29](../../src/tect/models.py#L29) | `supporting_ids: list[str]` | Explain the statement, track its state change and predict its effect on the worked example. |
| [30](../../src/tect/models.py#L30) | `contradicting_ids: list[str]` | Explain the statement, track its state change and predict its effect on the worked example. |
| [31](../../src/tect/models.py#L31) | `policy_version: str = "v0.1"` | Explain the statement, track its state change and predict its effect on the worked example. |
## Assessment and verification

A learner must explain the model, trace the capstone, identify a counterexample and state the scope boundary. Assess these four competencies equally; a numerical score cannot compensate for an unsupported scientific or operational claim.

Relevant existing checks:

- [tests/test_anchor_export.py](../../tests/test_anchor_export.py)
- [tests/test_approved_provider_targets.py](../../tests/test_approved_provider_targets.py)
- [tests/test_atomic_provenance.py](../../tests/test_atomic_provenance.py)

Follow [README](../../README.md) for environment and installed-package instructions. Read scripts before execution; source-reading exercises do not authorize provider calls, model downloads, live orders, hardware actions or messages. Synthetic fixtures establish software behavior only. This documentation change does not report those exercises as already executed.

## Interoperability and adoption gate

Retain explicit domain contracts. Shared assurance records should refer to domain evidence and its assumptions rather than relabeling graph reachability, homology, statistical calibration and epistemic acceptance as interchangeable quantities. The canonical ResearchOs controller remains owned by ResearchOs; this curriculum does not create another controller fork.

Adopt additional mathematics only after a versioned experiment demonstrates a useful operation, the scorecard has evidence, the simpler baseline is inadequate and existing conformance checks remain satisfied. Hash chains do not authenticate evidence or prevent an administrator from rewriting history.
