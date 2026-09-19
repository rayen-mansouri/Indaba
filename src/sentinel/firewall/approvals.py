"""Protected, one-time, state-bound approval records."""

from __future__ import annotations

import hashlib
import threading
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"


class ApprovalStatus(StrEnum):
    VALID = "valid"
    MISSING = "missing"
    MISMATCH = "mismatch"
    DENIED = "denied"
    EXPIRED = "expired"
    STALE_STATE = "stale_state"
    STALE_POLICY = "stale_policy"
    INVALID_ROLE = "invalid_role"
    REPLAYED = "replayed"


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: str = Field(pattern=r"^apr_[a-f0-9]{24}$")
    issuer_id: str = Field(min_length=1, max_length=128)
    issuer_role: str = Field(min_length=1, max_length=64)
    task_id: str = Field(min_length=1, max_length=160)
    action_digest: str = Field(min_length=1, max_length=128)
    policy_version: int = Field(ge=1)
    policy_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    state_version: int = Field(ge=0)
    expires_at: datetime
    decision: ApprovalDecision
    consumed: bool = False


class ApprovalStore:
    """Not exposed through agent tools; check-and-consume is lock-protected."""

    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}
        self._counter = 0
        self._lock = threading.Lock()

    @property
    def records(self) -> tuple[ApprovalRecord, ...]:
        with self._lock:
            return tuple(self._records.values())

    def issue(
        self,
        *,
        issuer_id: str,
        issuer_role: str,
        task_id: str,
        action_digest: str,
        policy_version: int,
        policy_hash: str,
        state_version: int,
        expires_at: datetime,
        decision: ApprovalDecision,
    ) -> ApprovalRecord:
        with self._lock:
            material = f"{task_id}:{action_digest}:{self._counter}".encode()
            self._counter += 1
            record = ApprovalRecord(
                record_id="apr_" + hashlib.sha256(material).hexdigest()[:24],
                issuer_id=issuer_id,
                issuer_role=issuer_role,
                task_id=task_id,
                action_digest=action_digest,
                policy_version=policy_version,
                policy_hash=policy_hash,
                state_version=state_version,
                expires_at=expires_at,
                decision=decision,
            )
            self._records[record.record_id] = record
            return record

    def status(
        self,
        *,
        task_id: str,
        action_digest: str,
        policy_version: int,
        policy_hash: str,
        state_version: int,
        allowed_roles: tuple[str, ...],
        now: datetime,
    ) -> ApprovalStatus:
        with self._lock:
            return self._status(
                task_id,
                action_digest,
                policy_version,
                policy_hash,
                state_version,
                allowed_roles,
                now,
            )[0]

    def consume(
        self,
        *,
        task_id: str,
        action_digest: str,
        policy_version: int,
        policy_hash: str,
        state_version: int,
        allowed_roles: tuple[str, ...],
        now: datetime,
    ) -> ApprovalStatus:
        with self._lock:
            status, record = self._status(
                task_id,
                action_digest,
                policy_version,
                policy_hash,
                state_version,
                allowed_roles,
                now,
            )
            if status is ApprovalStatus.VALID and record is not None:
                self._records[record.record_id] = record.model_copy(update={"consumed": True})
            return status

    def _status(
        self,
        task_id: str,
        action_digest: str,
        policy_version: int,
        policy_hash: str,
        state_version: int,
        allowed_roles: tuple[str, ...],
        now: datetime,
    ) -> tuple[ApprovalStatus, ApprovalRecord | None]:
        task_records = [record for record in self._records.values() if record.task_id == task_id]
        exact = [record for record in task_records if record.action_digest == action_digest]
        if not exact:
            return (ApprovalStatus.MISMATCH if task_records else ApprovalStatus.MISSING), None
        record = exact[-1]
        if record.decision is ApprovalDecision.DENIED:
            return ApprovalStatus.DENIED, record
        if record.consumed:
            return ApprovalStatus.REPLAYED, record
        if now >= record.expires_at:
            return ApprovalStatus.EXPIRED, record
        if record.policy_version != policy_version or record.policy_hash != policy_hash:
            return ApprovalStatus.STALE_POLICY, record
        if record.state_version != state_version:
            return ApprovalStatus.STALE_STATE, record
        if record.issuer_role not in allowed_roles:
            return ApprovalStatus.INVALID_ROLE, record
        return ApprovalStatus.VALID, record
