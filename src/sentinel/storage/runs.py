"""Append-only run artifacts: JSONL event streams, run summaries, and scorecards."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from sentinel.core.events import Event, event_to_json

SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]+")
MAX_ID_LENGTH = 120


class ArtifactError(ValueError):
    pass


def sanitize_id(raw: str) -> str:
    """Make an identifier safe for use as a single filename component."""
    cleaned = SAFE_ID.sub("-", raw).strip(".-")
    cleaned = re.sub(r"\.{2,}", ".", cleaned)[:MAX_ID_LENGTH]
    if not cleaned:
        raise ArtifactError(f"identifier {raw!r} is empty after sanitization")
    return cleaned


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, *parts: str) -> Path:
        path = self.root.joinpath(*(sanitize_id(p) for p in parts))
        resolved_root = self.root.resolve()
        if not path.resolve().is_relative_to(resolved_root):
            raise ArtifactError("artifact path escapes the artifact root")
        return path

    def unique_group(self, name: str) -> str:
        """Return ``name`` or ``name-N`` so a new evaluation never collides with an existing one."""
        base = sanitize_id(name)
        candidate, counter = base, 2
        while (self.root / candidate).exists():
            candidate = f"{base}-{counter}"
            counter += 1
        return candidate

    def prepare_event_path(self, group: str, run_id: str) -> Path:
        """Return a validated unused path for an incrementally written event stream."""
        path = self._path(group, f"{run_id}.jsonl")
        if path.exists():
            raise ArtifactError(f"event artifact already exists: {path}")
        return path

    def write_events(self, group: str, run_id: str, events: Iterable[Event]) -> Path:
        path = self._path(group, f"{run_id}.jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        # "x" mode: never overwrite an existing run artifact.
        with path.open("x", encoding="utf-8") as handle:
            for event in events:
                handle.write(event_to_json(event) + "\n")
        return path

    def write_json(self, group: str, name: str, data: dict[str, Any]) -> Path:
        path = self._path(group, f"{name}.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        return path


def read_events(path: Path) -> list[Event]:
    events = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                events.append(Event.model_validate_json(line))
            except ValueError as exc:
                raise ArtifactError(f"{path}:{number}: invalid event: {exc}") from exc
    return events
