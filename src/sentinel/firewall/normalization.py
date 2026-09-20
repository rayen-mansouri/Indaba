"""Strict trusted adapters and canonical action construction."""

from __future__ import annotations

import re
from functools import lru_cache

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from sentinel.core.actions import ActionType, CandidateAction
from sentinel.firewall.provenance import transformed_text_variants
from sentinel.firewall.records import FieldDependency, NormalizedAction, ObservedContent
from sentinel.firewall.toolspecs import ToolManifest
from sentinel.tools.base import Tool


class ActionNormalizationError(ValueError):
    def __init__(self, reason_code: str, detail: str) -> None:
        self.reason_code = reason_code
        super().__init__(detail)


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DestinationAlias(_Frozen):
    canonical: str = Field(min_length=1, max_length=256)
    aliases: tuple[str, ...] = ()


class DestinationMap(_Frozen):
    aliases: tuple[DestinationAlias, ...] = ()
    internal_email_domains: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _aliases_are_unambiguous(self) -> DestinationMap:
        values = [value.strip().lower() for item in self.aliases for value in (item.canonical, *item.aliases)]
        if len(values) != len(set(values)):
            raise ValueError("destination aliases must be unique")
        return self

    def canonicalize(self, value: str) -> str:
        normalized = value.strip().lower()
        for item in self.aliases:
            if normalized in {alias.strip().lower() for alias in (item.canonical, *item.aliases)}:
                canonical = item.canonical.strip()
                return canonical.lower() if "@" in canonical else canonical
        stripped = value.strip()
        return stripped.lower() if "@" in stripped else stripped


@lru_cache(maxsize=2048)
def _comparable(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _depends_on(value: object, observed: ObservedContent) -> bool:
    rendered = str(value)
    needle = _comparable(rendered)
    haystack = _comparable(observed.content)
    if not needle or not haystack:
        return False
    if needle in haystack:
        return True
    tokens = {token for token in re.findall(r"[a-z0-9]+", str(value).lower()) if len(token) >= 4}
    observed_tokens = set(re.findall(r"[a-z0-9]+", observed.content.lower()))
    if bool(tokens) and len(tokens & observed_tokens) / len(tokens) >= 0.5:
        return True
    # Candidate values can re-encode previously observed data. Decode the value
    # before matching so outbound sensitivity survives reversible transforms.
    for _, variant in transformed_text_variants(rendered):
        transformed = _comparable(variant)
        if len(transformed) >= 8 and (transformed in haystack or (len(haystack) >= 8 and haystack in transformed)):
            return True
    return False


class TrustedActionAdapters:
    def __init__(self, tools: tuple[Tool, ...], manifest: ToolManifest, destinations: DestinationMap) -> None:
        self._tools = {tool.name: tool for tool in tools}
        self.manifest = manifest
        self.destinations = destinations

    def normalize(
        self,
        proposal: CandidateAction,
        observed: tuple[ObservedContent, ...],
    ) -> NormalizedAction:
        if proposal.type is not ActionType.TOOL_CALL:
            dependencies = self._field_dependencies({"content": proposal.content or ""}, observed)
            node_ids = tuple(dict.fromkeys(node for item in dependencies for node in item.node_ids))
            return NormalizedAction(
                raw_proposal=proposal,
                executable=proposal,
                dependency_node_ids=node_ids,
                field_dependencies=dependencies,
                normalizer_version=self.manifest.normalizer_version,
                action_digest=proposal.digest(),
            )
        tool_name = proposal.tool or ""
        tool = self._tools.get(tool_name)
        spec = self.manifest.get(tool_name)
        if tool is None or spec is None:
            raise ActionNormalizationError("UNKNOWN_TOOL", f"unknown or unsupported tool {tool_name!r}")
        candidate_arguments = dict(proposal.arguments)
        for field in spec.destination_fields:
            value = candidate_arguments.get(field)
            if isinstance(value, str):
                candidate_arguments[field] = self.destinations.canonicalize(value)
        try:
            validated = tool.args_model.model_validate(candidate_arguments)
        except ValidationError as exc:
            raise ActionNormalizationError("INVALID_TOOL_ARGUMENTS", str(exc)) from exc
        arguments = validated.model_dump(mode="json", exclude_none=True)
        executable = CandidateAction(type=ActionType.TOOL_CALL, tool=tool_name, arguments=arguments)
        dependencies = self._field_dependencies(arguments, observed)
        node_ids = tuple(dict.fromkeys(node for item in dependencies for node in item.node_ids))
        canonical_destinations = tuple(
            str(arguments[field]) for field in spec.destination_fields if arguments.get(field) is not None
        )
        return NormalizedAction(
            raw_proposal=proposal,
            executable=executable,
            canonical_destinations=canonical_destinations,
            dependency_node_ids=node_ids,
            field_dependencies=dependencies,
            tool_spec_version=spec.version,
            normalizer_version=spec.normalizer_version,
            action_digest=executable.digest(),
        )

    @staticmethod
    def _field_dependencies(
        fields: dict[str, object], observed: tuple[ObservedContent, ...]
    ) -> tuple[FieldDependency, ...]:
        dependencies = []
        for field, value in sorted(fields.items()):
            node_ids = tuple(
                dict.fromkeys(
                    node_id for item in observed if _depends_on(value, item) for node_id in item.source_node_ids
                )
            )
            if node_ids:
                dependencies.append(FieldDependency(field=field, node_ids=node_ids))
        return tuple(dependencies)
