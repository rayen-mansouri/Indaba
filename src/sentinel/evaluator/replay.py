"""Human-readable timelines from JSONL event artifacts. Only observable data is shown."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.core.events import Event, EventType
from sentinel.storage.runs import read_events

PREVIEW = 160


def _short(value: Any, limit: int = PREVIEW) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def describe(event: Event) -> str:
    p = event.payload
    match event.type:
        case EventType.USER_MESSAGE:
            return f"user (turn {p.get('turn')}): {_short(p.get('text', ''))}"
        case EventType.MEMORY_READ:
            return f"memory recalled: {', '.join(p.get('entries', []))}"
        case EventType.MEMORY_WRITE:
            return f"memory write {p.get('entry_id')} [{p.get('trust_level')}]: {_short(p.get('content', ''))}"
        case EventType.DEFENSE_DECISION:
            action = p.get("action", {})
            target = action.get("tool") or action.get("type")
            codes = ",".join(p.get("reason_codes", [])) or "-"
            error = f" error={p['defense_error']}" if p.get("defense_error") else ""
            return (
                f"defense {p.get('decision', '?').upper():8} {target} risk={p.get('risk_score')} codes={codes}{error}"
            )
        case EventType.ACTION_PROPOSAL:
            action = p.get("original_proposal", {})
            return f"firewall proposal {action.get('tool') or action.get('type')} digest={p.get('action_digest')}"
        case EventType.FIREWALL_DECISION:
            codes = ",".join(p.get("reason_codes", [])) or "-"
            return f"firewall {p.get('outcome', '?').upper():8} digest={p.get('action_digest')} codes={codes}"
        case EventType.ACTION_REWRITE:
            replacement = p.get("replacement", {})
            return f"rewrite -> {replacement.get('tool') or replacement.get('type')} digest={p.get('action_digest')}"
        case EventType.APPROVAL_RECORD:
            return f"approval {p.get('decision')} {p.get('tool')} digest={p.get('action_digest')}"
        case EventType.EXECUTOR_RECEIPT:
            status = "ok" if p.get("succeeded") else f"error: {p.get('error')}"
            return f"executor {p.get('tool')} {status} digest={p.get('action_digest')}"
        case EventType.STATE_VERIFIED:
            return f"state verified v{p.get('new_state_version')} digest={p.get('action_digest')}"
        case EventType.HUMAN_CONFIRMATION:
            return f"human {'approved' if p.get('approved') else 'denied'} {p.get('tool')}"
        case EventType.TOOL_REQUEST:
            return f"tool call {p.get('tool')}({_short(p.get('arguments', {}), 120)})"
        case EventType.TOOL_RESULT | EventType.RETRIEVAL_RESULT:
            status = "ok" if p.get("succeeded") else f"error: {p.get('error')}"
            effects = f" effects={p['effects']}" if p.get("effects") else ""
            return f"result {p.get('tool')} {status}{effects}"
        case EventType.MODEL_OUTPUT:
            return f"agent response{' (final)' if p.get('final') else ''}: {_short(p.get('content', ''))}"
        case EventType.POLICY_VIOLATION:
            return f"VIOLATION {p.get('severity', '').upper()} {p.get('rule_id')}: {_short(p.get('message', ''))}"
        case EventType.TASK_SUCCESS | EventType.TASK_FAILURE:
            return f"{event.type.value}: {_short(p.get('summary', ''))}"
    return event.type.value  # pragma: no cover


def render_timeline(events: list[Event]) -> list[str]:
    lines = []
    for event in events:
        ref = f" <{','.join(event.provenance_refs)}>" if event.provenance_refs else ""
        lines.append(f"[{event.seq:04d}] step {event.step_id:>2} {event.actor.value:<15} {describe(event)}{ref}")
    return lines


def replay_file(path: Path) -> list[str]:
    return render_timeline(read_events(path))
