"""Immutable trusted records accepted by the SENTINEL decision core."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinel.core.actions import CandidateAction
from sentinel.core.provenance import TrustLevel


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DataSensitivity(StrEnum):
    """Runtime sensitivity, including the fail-safe unknown state."""

    UNKNOWN = "unknown"
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        if self is DataSensitivity.UNKNOWN:
            return len(DataSensitivity)
        return list(DataSensitivity).index(self)


class Transformation(StrEnum):
    DIRECT = "direct"
    PARSE = "parse"
    BASE64_DECODE = "base64_decode"
    HEX_DECODE = "hex_decode"
    REVERSE = "reverse"
    WHITESPACE_JOIN = "whitespace_join"
    CONCATENATE = "concatenate"
    EXTRACT = "extract"
    SUMMARIZE = "summarize"
    REENCODE = "reencode"
    UNSUPPORTED = "unsupported"


class SourceNode(_Frozen):
    """Runtime-issued provenance node with lineage and run/session binding."""

    node_id: str = Field(pattern=r"^src_[A-Za-z0-9_-]{16,96}$")
    run_id: str = Field(min_length=1, max_length=160)
    session_id: str = Field(min_length=1, max_length=160)
    source_kind: str = Field(min_length=1, max_length=64)
    trust_label: TrustLevel
    sensitivity: DataSensitivity = DataSensitivity.UNKNOWN
    parent_ids: tuple[str, ...] = ()
    transformation: Transformation = Transformation.DIRECT

    @model_validator(mode="after")
    def _derived_nodes_have_parents(self) -> SourceNode:
        if self.transformation is not Transformation.DIRECT and not self.parent_ids:
            raise ValueError("transformed source nodes require at least one parent")
        if self.node_id in self.parent_ids:
            raise ValueError("a source node cannot be its own parent")
        return self


class AuthenticatedPrincipal(_Frozen):
    principal_id: str = Field(min_length=1, max_length=128)
    role: str = Field(min_length=1, max_length=64)
    authenticated_by: str = Field(min_length=1, max_length=128)


class ParameterConstraint(_Frozen):
    field: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    allowed_values: tuple[str, ...] = ()


class CapabilityGrant(_Frozen):
    """One authoritative grant; empty constraints grant no resources or destinations."""

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    capabilities: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    max_amount: float | None = Field(default=None, gt=0)
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    parameters: tuple[ParameterConstraint, ...] = ()

    @model_validator(mode="after")
    def _amount_has_currency(self) -> CapabilityGrant:
        if (self.max_amount is None) != (self.currency is None):
            raise ValueError("max_amount and currency must be set together")
        return self


class TaskScope(_Frozen):
    """Authenticated task authority supplied out of band, never parsed from message text."""

    task_id: str = Field(min_length=1, max_length=160)
    principal: AuthenticatedPrincipal
    grants: tuple[CapabilityGrant, ...]
    delegation_roles: tuple[str, ...] = ()
    issued_state_version: int = Field(ge=0)

    @model_validator(mode="after")
    def _unique_tools(self) -> TaskScope:
        names = [grant.tool for grant in self.grants]
        if len(names) != len(set(names)):
            raise ValueError("task scope contains duplicate tool grants")
        return self

    def grant_for(self, tool: str) -> CapabilityGrant | None:
        return next((grant for grant in self.grants if grant.tool == tool), None)


class ResourceState(_Frozen):
    resource: str = Field(min_length=1, max_length=160)
    lifecycle: str = Field(min_length=1, max_length=64)


class WorkflowState(_Frozen):
    """Authoritative state facts visible to the gate evaluator."""

    version: int = Field(ge=0)
    resources: tuple[ResourceState, ...] = ()
    succeeded_tools: tuple[str, ...] = ()

    def lifecycle_for(self, resource: str) -> str | None:
        match = next((item for item in self.resources if item.resource == resource), None)
        return match.lifecycle if match else None


class NormalizedAction(_Frozen):
    raw_proposal: CandidateAction
    executable: CandidateAction
    canonical_destinations: tuple[str, ...] = ()
    dependency_node_ids: tuple[str, ...] = ()
    tool_spec_version: str | None = None
    normalizer_version: str
    action_digest: str

    @model_validator(mode="after")
    def _digest_matches_executable(self) -> NormalizedAction:
        if self.action_digest != self.executable.digest():
            raise ValueError("action_digest does not match the executable action")
        return self


class ObservedContent(_Frozen):
    content: str = Field(max_length=20_000)
    source_node_ids: tuple[str, ...]


class DecisionContext(_Frozen):
    """The complete decision input; evaluator-only metadata is not representable."""

    run_id: str = Field(min_length=1, max_length=160)
    session_id: str = Field(min_length=1, max_length=160)
    step_id: int = Field(ge=1)
    live_agent_state: WorkflowState
    candidate: NormalizedAction
    provenance: tuple[SourceNode, ...]
    active_policy_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    task_scope: TaskScope
    observed_content: tuple[ObservedContent, ...] = ()


EVALUATOR_ONLY_FIELDS = frozenset(
    {
        "scenario_id",
        "scenario_path",
        "filename",
        "expected_outcome",
        "reference_plan",
        "success_conditions",
        "legitimate",
        "attack_label",
        "difficulty",
        "split",
    }
)

assert not EVALUATOR_ONLY_FIELDS.intersection(DecisionContext.model_fields)
