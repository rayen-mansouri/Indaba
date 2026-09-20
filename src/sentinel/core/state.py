"""Synthetic world state: collections of records with provenance metadata."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentinel.core.canary import CanaryRegistry
from sentinel.core.provenance import Provenance, Sensitivity, SourceType, TrustLevel
from sentinel.core.scenario import CanarySpec, Scenario, child_seed

META_KEY = "_meta"
MAX_FIXTURE_BYTES = 2_000_000


class StateError(ValueError):
    pass


def resolve_within(root: Path, relative: str) -> Path:
    """Resolve ``relative`` under ``root`` and refuse anything that escapes it."""
    candidate = Path(relative)
    if candidate.is_absolute():
        raise StateError(f"absolute paths are not allowed: {relative!r}")
    resolved_root = root.resolve()
    resolved = (resolved_root / candidate).resolve()
    if not resolved.is_relative_to(resolved_root):
        raise StateError(f"path escapes benchmark root: {relative!r}")
    return resolved


@dataclass(frozen=True)
class RecordMeta:
    source_type: SourceType
    trust_level: TrustLevel
    origin_actor: str
    sensitivity: Sensitivity

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RecordMeta:
        try:
            return cls(
                source_type=SourceType(data["source_type"]),
                trust_level=TrustLevel(data["trust_level"]),
                origin_actor=str(data["origin_actor"]),
                sensitivity=Sensitivity(data.get("sensitivity", "internal")),
            )
        except (KeyError, ValueError) as exc:
            raise StateError(f"invalid record metadata {data!r}: {exc}") from exc

    def to_dict(self) -> dict[str, str]:
        return {
            "source_type": self.source_type.value,
            "trust_level": self.trust_level.value,
            "origin_actor": self.origin_actor,
            "sensitivity": self.sensitivity.value,
        }


@dataclass(frozen=True)
class Effect:
    step_id: int
    name: str
    tool: str
    details: dict[str, Any]


@dataclass
class WorldState:
    domain: str
    seed: int
    collections: dict[str, dict[str, dict[str, Any]]]
    canaries: CanaryRegistry
    settings: dict[str, Any] = field(default_factory=dict)
    tool_output_overrides: dict[tuple[str, str], str] = field(default_factory=dict)
    effects: list[Effect] = field(default_factory=list)
    confirmations: set[str] = field(default_factory=set)
    counters: dict[str, int] = field(default_factory=dict)

    # ---- construction ---------------------------------------------------------------------
    @classmethod
    def from_scenario(cls, scenario: Scenario, root: Path, run_seed: int = 0) -> WorldState:
        path = resolve_within(root, scenario.fixture)
        if not path.is_file():
            raise StateError(f"fixture not found: {scenario.fixture}")
        if path.stat().st_size > MAX_FIXTURE_BYTES:
            raise StateError(f"fixture too large: {scenario.fixture}")
        data = json.loads(path.read_text())
        if data.get("domain") != scenario.domain.value:
            raise StateError(f"fixture domain {data.get('domain')!r} does not match scenario domain {scenario.domain}")
        specs: dict[str, CanarySpec] = {}
        try:
            for raw in data.get("canaries", []):
                spec = CanarySpec.model_validate(raw)
                specs[spec.name] = spec
        except ValidationError as exc:
            raise StateError(f"invalid canary in fixture: {exc}") from exc
        for spec in scenario.canaries:
            specs[spec.name] = spec
        seed = child_seed(scenario.seed, "run", run_seed)
        registry = CanaryRegistry.from_specs(seed, list(specs.values()))

        raw_collections: dict[str, list[dict[str, Any]]] = copy.deepcopy(data.get("collections", {}))
        for name, records in scenario.extra_records.items():
            raw_collections.setdefault(name, []).extend(copy.deepcopy(records))

        substituted = json.loads(registry.substitute(json.dumps(raw_collections)))
        collections: dict[str, dict[str, dict[str, Any]]] = {}
        for name, records in substituted.items():
            table: dict[str, dict[str, Any]] = {}
            for record in records:
                record_id = record.get("id")
                if not isinstance(record_id, str) or not record_id:
                    raise StateError(f"record in {name!r} is missing a string 'id'")
                if record_id in table:
                    raise StateError(f"duplicate id {record_id!r} in collection {name!r}")
                RecordMeta.from_dict(record.get(META_KEY, {}))
                table[record_id] = record
            collections[name] = table
        settings = data.get("settings", {})
        if not isinstance(settings, dict):
            raise StateError("fixture 'settings' must be a mapping")
        return cls(
            domain=scenario.domain.value,
            seed=seed,
            collections=collections,
            canaries=registry,
            settings=settings,
        )

    # ---- queries --------------------------------------------------------------------------
    def table(self, collection: str) -> dict[str, dict[str, Any]]:
        return self.collections.setdefault(collection, {})

    def get(self, collection: str, record_id: str) -> dict[str, Any] | None:
        return self.collections.get(collection, {}).get(record_id)

    def find(self, collection: str, where: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        where = where or {}
        return [
            record
            for record in self.collections.get(collection, {}).values()
            if all(loose_equal(record.get(key), value) for key, value in where.items())
        ]

    def meta(self, collection: str, record_id: str) -> RecordMeta:
        record = self.get(collection, record_id)
        if record is None:
            raise StateError(f"unknown record {collection}/{record_id}")
        return RecordMeta.from_dict(record[META_KEY])

    def provenance_for(self, collection: str, record_id: str, retrieved_via: str, timestamp: datetime) -> Provenance:
        meta = self.meta(collection, record_id)
        return Provenance(
            source_type=meta.source_type,
            source_id=record_id,
            trust_level=meta.trust_level,
            origin_actor=meta.origin_actor,
            retrieved_via=retrieved_via,
            sensitivity=meta.sensitivity,
            timestamp=timestamp,
        )

    @staticmethod
    def public_view(record: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in record.items() if key != META_KEY}

    # ---- mutations ------------------------------------------------------------------------
    def next_id(self, prefix: str) -> str:
        count = self.counters.get(prefix, 0) + 1
        self.counters[prefix] = count
        return f"{prefix}-{count:04d}"

    def insert(self, collection: str, prefix: str, record: dict[str, Any], meta: RecordMeta) -> str:
        record_id = self.next_id(prefix)
        while record_id in self.table(collection):
            record_id = self.next_id(prefix)
        self.table(collection)[record_id] = {"id": record_id, **record, META_KEY: meta.to_dict()}
        return record_id

    def record_effect(self, step_id: int, name: str, tool: str, details: dict[str, Any]) -> None:
        self.effects.append(Effect(step_id=step_id, name=name, tool=tool, details=details))

    def has_effect(self, name: str) -> bool:
        return any(effect.name == name for effect in self.effects)

    def snapshot(self) -> dict[str, Any]:
        """Return a detached view suitable for hashing, inspection, or replay.

        The firewall currently serializes this immediately, but keeping the public method detached
        prevents a caller from mutating authoritative state through a value named ``snapshot``.
        """
        return copy.deepcopy(
            {
                "collections": self.collections,
                "effects": [effect.__dict__ for effect in self.effects],
            }
        )


def loose_equal(left: Any, right: Any) -> bool:
    if isinstance(left, str) and isinstance(right, str):
        return left.strip().lower() == right.strip().lower()
    if isinstance(left, int | float) and isinstance(right, int | float):
        return float(left) == float(right)
    return bool(left == right)
