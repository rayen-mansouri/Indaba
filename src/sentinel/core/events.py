"""Immutable event records and the append-only event log."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventType(StrEnum):
    USER_MESSAGE = "user_message"
    RETRIEVAL_RESULT = "retrieval_result"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    TOOL_REQUEST = "tool_request"
    TOOL_RESULT = "tool_result"
    MODEL_OUTPUT = "model_output"
    DEFENSE_DECISION = "defense_decision"
    ACTION_PROPOSAL = "action_proposal"
    FIREWALL_DECISION = "firewall_decision"
    ACTION_REWRITE = "action_rewrite"
    APPROVAL_RECORD = "approval_record"
    EXECUTOR_RECEIPT = "executor_receipt"
    STATE_VERIFIED = "state_verified"
    HUMAN_CONFIRMATION = "human_confirmation"
    POLICY_VIOLATION = "policy_violation"
    TASK_SUCCESS = "task_success"
    TASK_FAILURE = "task_failure"


class Actor(StrEnum):
    USER = "user"
    AGENT = "agent"
    DEFENSE = "defense"
    TOOL_GATEWAY = "tool_gateway"
    HUMAN_SIMULATOR = "human_simulator"
    EVALUATOR = "evaluator"


class Event(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    run_id: str
    step_id: int = Field(ge=0)
    seq: int = Field(ge=0)
    type: EventType
    timestamp: datetime
    actor: Actor
    payload: dict[str, Any] = Field(default_factory=dict)
    provenance_refs: tuple[str, ...] = ()
    policy: dict[str, Any] = Field(default_factory=dict)


class LogicalClock:
    """Deterministic timestamps: artifacts are byte-identical across reruns of the same seed."""

    def __init__(self, seed: int, start: datetime | None = None) -> None:
        base = start or datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
        self._now = base + timedelta(minutes=seed % 10_000)

    def tick(self, seconds: int = 1) -> datetime:
        self._now += timedelta(seconds=seconds)
        return self._now


class EventLog:
    """Append-only event log with an optional incrementally flushed JSONL mirror."""

    def __init__(self, run_id: str, clock: LogicalClock, sink_path: Path | None = None) -> None:
        self.run_id = run_id
        self._clock = clock
        self._events: list[Event] = []
        self._sink_path = sink_path
        self._sink_handle: Any = None
        if sink_path is not None:
            sink_path.parent.mkdir(parents=True, exist_ok=True)
            # "x" mode: fails if the artifact already exists, same guarantee as the previous
            # touch(exist_ok=False), and gives us one handle held open for the run's lifetime
            # instead of reopening the file on every append().
            self._sink_handle = sink_path.open("x", encoding="utf-8", newline="\n")

    def append(
        self,
        type: EventType,
        actor: Actor,
        step_id: int,
        payload: dict[str, Any] | None = None,
        provenance_refs: tuple[str, ...] = (),
        policy: dict[str, Any] | None = None,
    ) -> Event:
        seq = len(self._events)
        digest = hashlib.sha256(f"{self.run_id}:{seq}:{type}".encode()).hexdigest()[:12]
        event = Event(
            event_id=f"ev-{seq:04d}-{digest}",
            run_id=self.run_id,
            step_id=step_id,
            seq=seq,
            type=type,
            timestamp=self._clock.tick(),
            actor=actor,
            payload=payload or {},
            provenance_refs=provenance_refs,
            policy=policy or {},
        )
        self._events.append(event)
        if self._sink_handle is not None:
            # flush() (no reopen) still makes the event visible immediately for the offline
            # viewer's live-follow mode; the handle itself is held open for the run's lifetime
            # and closed via close() by the caller.
            self._sink_handle.write(event_to_json(event) + "\n")
            self._sink_handle.flush()
        return event

    def close(self) -> None:
        """Close the sink handle, if one is open. Safe to call more than once."""
        if self._sink_handle is not None:
            self._sink_handle.close()
            self._sink_handle = None

    def __iter__(self) -> Iterator[Event]:
        return iter(self._events)

    def __len__(self) -> int:
        return len(self._events)

    @property
    def events(self) -> tuple[Event, ...]:
        return tuple(self._events)

    def of_type(self, *types: EventType) -> list[Event]:
        return [event for event in self._events if event.type in types]


def event_to_json(event: Event) -> str:
    return json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
