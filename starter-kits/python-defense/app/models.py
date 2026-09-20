"""Self-contained copies of the SENTINEL v1 defense API schemas.

The request *envelope* ignores unknown fields, so your service keeps working when organizers add
context around the action. The action shape itself and every response field are strict, exactly as
strict as ``sentinel.core.actions``: the evaluator rejects anything that does not match, and a
rejected response is treated as an unavailable defense — which fails closed and blocks every tool
call for the rest of the run. Keep the constraints below in sync with the simulator.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_METADATA_BYTES = 4_096
REASON_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{1,63}$"


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class CandidateAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["respond", "tool_call", "memory_write", "request_confirmation"]
    tool: str | None = None
    arguments: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    content: str | None = None
    final: bool = False
    confirmation_for: CandidateAction | None = None


class Provenance(_Lenient):
    source_type: str
    source_id: str
    trust_level: Literal[
        "system_policy",
        "authenticated_user",
        "trusted_internal",
        "untrusted_internal",
        "untrusted_external",
        "adversary_controlled",
    ]
    origin_actor: str
    retrieved_via: str
    sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"


class ProvenanceRecord(_Lenient):
    id: str
    provenance: Provenance


class ConversationItem(_Lenient):
    role: str
    kind: str
    content: str
    provenance_ids: list[str] = Field(default_factory=list)


class ObservationView(_Lenient):
    kind: str
    content: str
    provenance_ids: list[str] = Field(default_factory=list)


class HistoryDigest(_Lenient):
    steps_taken: int = 0
    turn_index: int = 0
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    confirmations_granted: list[str] = Field(default_factory=list)
    blocked_count: int = 0
    escalated_count: int = 0
    least_trusted_seen: str | None = None
    most_sensitive_seen: str | None = None


class DefenseRequest(_Lenient):
    run_id: str
    step_id: int
    user_goal: str
    conversation: list[ConversationItem] = Field(default_factory=list)
    observation: ObservationView | None = None
    candidate_action: CandidateAction
    policy_context: dict[str, Any] = Field(default_factory=dict)
    provenance: list[ProvenanceRecord] = Field(default_factory=list)
    history_digest: HistoryDigest = Field(default_factory=HistoryDigest)


class DefenseDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["allow", "block", "escalate", "rewrite"]
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list, max_length=16)
    explanation: str | None = Field(default=None, max_length=500)
    rewritten_action: CandidateAction | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reason_codes")
    @classmethod
    def _valid_codes(cls, codes: list[str]) -> list[str]:
        for code in codes:
            if not re.fullmatch(REASON_CODE_PATTERN, code):
                raise ValueError(f"invalid reason code {code!r}; use UPPER_SNAKE_CASE")
        return codes

    @field_validator("metadata")
    @classmethod
    def _bounded_metadata(cls, metadata: dict[str, Any]) -> dict[str, Any]:
        try:
            size = len(json.dumps(metadata))
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON-serializable") from exc
        if size > MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {MAX_METADATA_BYTES} bytes")
        return metadata

    @model_validator(mode="after")
    def _rewrite_needs_action(self) -> DefenseDecision:
        if (self.decision == "rewrite") != (self.rewritten_action is not None):
            raise ValueError("rewritten_action is required for, and only for, decision 'rewrite'")
        return self
