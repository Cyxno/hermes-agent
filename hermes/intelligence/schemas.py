"""Structured AI output schemas (spec §18).

Internal decisions are ALWAYS validated pydantic objects; free prose is allowed
only in human-facing explanation fields. Invalid output -> reject/retry/escalate.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class ProposedAction(BaseModel):
    capability: str = Field(description="capability name from the Hermes capability registry")
    target: str = Field(description="entity the action applies to")
    args: dict = Field(default_factory=dict)
    reason: str = ""

    @field_validator("capability", "target")
    @classmethod
    def _no_shell(cls, value: str) -> str:
        if any(ch in value for ch in "\n\r;|&$`"):
            raise ValueError("capability/target must be plain identifiers")
        return value.strip()[:200]


class Diagnosis(BaseModel):
    rootCause: str
    confidence: float = Field(ge=0.0, le=1.0)
    knownCause: bool = False
    multipleRootCauses: bool = False
    insufficientEvidence: bool = False
    evidence: list[str] = Field(default_factory=list, max_length=20)
    recommendedRunbook: str | None = None
    proposedActions: list[ProposedAction] = Field(default_factory=list, max_length=5)
    requiresEscalation: bool = False
    requiresHumanApproval: bool = False
    explanation: str = ""

    @field_validator("rootCause", "explanation")
    @classmethod
    def _bound_text(cls, value: str) -> str:
        return value.strip()[:1200]


DIAGNOSIS_INSTRUCTION = """Antwoord UITSLUITEND met één JSON-object dat aan dit schema voldoet:
{"rootCause": str, "confidence": float 0..1, "knownCause": bool,
 "multipleRootCauses": bool, "insufficientEvidence": bool,
 "evidence": [str], "recommendedRunbook": str|null,
 "proposedActions": [{"capability": str, "target": str, "args": {}, "reason": str}],
 "requiresEscalation": bool, "requiresHumanApproval": bool, "explanation": str}
Geen prose buiten de JSON. Gebruik alleen capability-namen uit de lijst."""


def diagnosis_json_schema() -> dict:
    """Native structured-output schema (OpenRouter json_schema) uit het pydantic-model.

    De pydantic-validatie blijft het harde contract; dit schema dwingt het
    formaat al aan de provider-kant af.
    """
    return Diagnosis.model_json_schema()
