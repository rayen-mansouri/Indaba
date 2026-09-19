"""Verification for SENTINEL's digest-linked security trace continuity."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.core.actions import CandidateAction
from sentinel.core.events import Actor, Event, EventType

SECURITY_EVENT_TYPES = frozenset(
    {
        EventType.ACTION_PROPOSAL,
        EventType.FIREWALL_DECISION,
        EventType.ACTION_REWRITE,
        EventType.APPROVAL_RECORD,
        EventType.EXECUTOR_RECEIPT,
        EventType.STATE_VERIFIED,
    }
)

_LINK_FIELDS = (
    "action_digest",
    "policy_version",
    "policy_hash",
    "tool_spec_version",
    "normalizer_version",
    "authorized_state_version",
    "task_id",
)

_EMITTERS: dict[EventType, tuple[str, Actor]] = {
    EventType.ACTION_PROPOSAL: ("decision_service", Actor.DEFENSE),
    EventType.FIREWALL_DECISION: ("decision_service", Actor.DEFENSE),
    EventType.ACTION_REWRITE: ("decision_service", Actor.DEFENSE),
    EventType.APPROVAL_RECORD: ("decision_service", Actor.DEFENSE),
    EventType.EXECUTOR_RECEIPT: ("guarded_executor", Actor.TOOL_GATEWAY),
    EventType.STATE_VERIFIED: ("guarded_executor", Actor.TOOL_GATEWAY),
}


class TraceIntegrityError(ValueError):
    pass


@dataclass(frozen=True)
class TraceContinuityReport:
    security_events: int
    action_chains: int
    executed_actions: int


def _link(event: Event) -> tuple[object, ...]:
    missing = [field for field in _LINK_FIELDS if field not in event.payload]
    if missing:
        raise TraceIntegrityError(f"{event.event_id} is missing trace link fields {missing}")
    digest = event.payload["action_digest"]
    policy_hash = event.payload["policy_hash"]
    if not isinstance(digest, str) or len(digest) != 24:
        raise TraceIntegrityError(f"{event.event_id} has an invalid action digest")
    if not isinstance(policy_hash, str) or len(policy_hash) != 64:
        raise TraceIntegrityError(f"{event.event_id} has an invalid policy hash")
    return tuple(event.payload[field] for field in _LINK_FIELDS)


def verify_digest_linked_trace(events: tuple[Event, ...] | list[Event]) -> TraceContinuityReport:
    """Reject missing links, invalid emitters, digest drift, and receipt/state mismatches."""
    security = [event for event in events if event.type in SECURITY_EVENT_TYPES]
    by_digest: dict[str, list[Event]] = {}
    for event in security:
        expected_emitter, expected_actor = _EMITTERS[event.type]
        if event.payload.get("emitter") != expected_emitter or event.actor is not expected_actor:
            raise TraceIntegrityError(f"{event.event_id} has an untrusted security-event emitter")
        link = _link(event)
        by_digest.setdefault(str(link[0]), []).append(event)

    executed = 0
    for digest, chain in by_digest.items():
        proposals = [event for event in chain if event.type is EventType.ACTION_PROPOSAL]
        decisions = [event for event in chain if event.type is EventType.FIREWALL_DECISION]
        rewrites = [event for event in chain if event.type is EventType.ACTION_REWRITE]
        approvals = [event for event in chain if event.type is EventType.APPROVAL_RECORD]
        receipts = [event for event in chain if event.type is EventType.EXECUTOR_RECEIPT]
        states = [event for event in chain if event.type is EventType.STATE_VERIFIED]
        if (decisions or rewrites or approvals or receipts or states) and not proposals:
            raise TraceIntegrityError(f"action {digest} has security events without a proposal")
        canonical = _link(proposals[0]) if proposals else None
        for event in chain:
            if canonical is not None and _link(event) != canonical:
                raise TraceIntegrityError(f"action {digest} has inconsistent trace linkage at {event.event_id}")
        if decisions and min(event.seq for event in decisions) < min(event.seq for event in proposals):
            raise TraceIntegrityError(f"action {digest} has a decision before its proposal")
        if rewrites:
            for event in rewrites:
                replacement = CandidateAction.model_validate(event.payload.get("replacement"))
                if replacement.digest() != digest:
                    raise TraceIntegrityError(f"{event.event_id} replacement digest does not match its trace")
        if receipts:
            executed += 1
            if not decisions:
                raise TraceIntegrityError(f"executed action {digest} has no firewall decision")
            if len(receipts) != 1 or len(states) != 1:
                raise TraceIntegrityError(f"executed action {digest} must have one receipt and one state result")
            receipt = receipts[0]
            state = states[0]
            if receipt.seq >= state.seq:
                raise TraceIntegrityError(f"action {digest} state result does not follow its receipt")
            executed_action = CandidateAction.model_validate(receipt.payload.get("executed_action"))
            if executed_action.digest() != digest:
                raise TraceIntegrityError(f"{receipt.event_id} does not match the executed action digest")
        elif states:
            raise TraceIntegrityError(f"action {digest} has a state result without an executor receipt")
    return TraceContinuityReport(
        security_events=len(security),
        action_chains=len(by_digest),
        executed_actions=executed,
    )
