"""The defense contract. Participants implement ``Defense.decide`` in-process or over HTTP."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from sentinel.core.actions import CandidateAction, DefenseDecision
from sentinel.core.provenance import Provenance


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProvenanceRecord(_Strict):
    id: str
    provenance: Provenance


class ConversationItem(_Strict):
    role: str = Field(pattern=r"^(user|agent|tool|memory|safety|human)$")
    kind: str
    content: str
    provenance_ids: list[str] = Field(default_factory=list)


class ObservationView(_Strict):
    kind: str
    content: str
    provenance_ids: list[str] = Field(default_factory=list)


class ToolCallSummary(_Strict):
    step_id: int
    tool: str
    decision: str
    succeeded: bool | None = None


class HistoryDigest(_Strict):
    steps_taken: int = 0
    turn_index: int = 0
    tool_calls: list[ToolCallSummary] = Field(default_factory=list)
    confirmations_granted: list[str] = Field(default_factory=list)
    blocked_count: int = 0
    escalated_count: int = 0
    least_trusted_seen: str | None = None
    most_sensitive_seen: str | None = None


class DefenseRequest(_Strict):
    """Everything a defense may see. Never contains reference plans, labels, or attack payloads."""

    run_id: str
    step_id: int
    runtime_timestamp: datetime | None = None
    user_goal: str
    conversation: list[ConversationItem] = Field(default_factory=list)
    observation: ObservationView | None = None
    candidate_action: CandidateAction
    policy_context: dict[str, Any] = Field(default_factory=dict)
    provenance: list[ProvenanceRecord] = Field(default_factory=list)
    history_digest: HistoryDigest = Field(default_factory=HistoryDigest)


class Defense(ABC):
    name: str = "defense"

    @abstractmethod
    def decide(self, request: DefenseRequest) -> DefenseDecision: ...

    def close(self) -> None:
        """Release resources (HTTP clients, models)."""
        return None
