from pathlib import Path

import pytest

from sentinel.core.events import Actor, EventLog, EventType, LogicalClock
from sentinel.evaluator.replay import render_timeline, replay_file
from sentinel.storage.runs import ArtifactError, ArtifactStore, read_events, sanitize_id


def sample_log() -> EventLog:
    log = EventLog("run-1", LogicalClock(42))
    log.append(EventType.USER_MESSAGE, Actor.USER, 0, {"turn": 0, "text": "hello"})
    log.append(
        EventType.DEFENSE_DECISION,
        Actor.DEFENSE,
        1,
        {
            "action": {"type": "tool_call", "tool": "email_read"},
            "decision": "allow",
            "risk_score": 0.1,
            "reason_codes": ["OK"],
        },
    )
    log.append(
        EventType.POLICY_VIOLATION,
        Actor.EVALUATOR,
        1,
        {"severity": "critical", "rule_id": "TOOL_PERMISSION", "message": "nope"},
    )
    return log


def test_event_log_flushes_each_event_to_incremental_jsonl(tmp_path) -> None:  # type: ignore[no-untyped-def]
    sink = tmp_path / "live.jsonl"
    log = EventLog("live-run", LogicalClock(7), sink_path=sink)

    first = log.append(EventType.USER_MESSAGE, Actor.USER, 0, {"text": "hello"})
    assert sink.read_text(encoding="utf-8").count("\n") == 1
    assert first.event_id in sink.read_text(encoding="utf-8")

    second = log.append(EventType.MODEL_OUTPUT, Actor.AGENT, 1, {"content": "done"})
    lines = sink.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and second.event_id in lines[1]
    log.close()
    log.close()
    sink.rename(tmp_path / "closed.jsonl")


def test_event_ids_and_timestamps_are_deterministic() -> None:
    a, b = sample_log(), sample_log()
    assert [e.model_dump() for e in a] == [e.model_dump() for e in b]
    assert [e.seq for e in a] == [0, 1, 2]


def test_jsonl_roundtrip_and_timeline(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    path = store.write_events("group", "run-1", sample_log().events)
    events = read_events(path)
    assert len(events) == 3
    lines = replay_file(path)
    assert "defense ALLOW" in lines[1] and "VIOLATION CRITICAL TOOL_PERMISSION" in lines[2]
    assert render_timeline(events) == lines


def test_artifacts_are_append_only(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    store.write_events("g", "run", sample_log().events)
    with pytest.raises(FileExistsError):
        store.write_events("g", "run", sample_log().events)
    assert store.unique_group("g") == "g-2"


def test_invalid_jsonl_reports_line(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text('{"not": "an event"}\n')
    with pytest.raises(ArtifactError, match=":1:"):
        read_events(path)


def test_sanitize_id() -> None:
    assert sanitize_id("../../etc/passwd") == "etc-passwd"
    assert sanitize_id("run id with spaces/and\\slashes") == "run-id-with-spaces-and-slashes"
    assert len(sanitize_id("a" * 500)) == 120
    with pytest.raises(ArtifactError):
        sanitize_id("../..")
