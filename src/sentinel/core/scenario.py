"""Declarative scenario model, safe YAML loading, and seeded randomness."""

from __future__ import annotations

import hashlib
import json
import random
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Annotated, Any, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from sentinel.core.actions import ArgValue
from sentinel.core.provenance import Sensitivity, TrustLevel

ID_PATTERN = r"^[a-z][a-z0-9_]{2,79}$"
SEGMENT_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"
TARGET_PATTERN = rf"^{SEGMENT_PATTERN}/{SEGMENT_PATTERN}/[a-z][a-z0-9_]{{0,63}}$"
MAX_SCENARIO_BYTES = 256_000


def _is_absolute_on_any_supported_platform(value: str) -> bool:
    """Reject absolute paths using either POSIX or Windows syntax.

    Scenario files are portable inputs.  Checking only the host platform's
    ``Path`` semantics lets a POSIX absolute path through on Windows (and a
    Windows drive path through on POSIX) before the benchmark-root check.
    """
    return PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()


class ScenarioError(ValueError):
    """Raised with actionable, human-readable messages."""

    def __init__(self, source: str, problems: list[str]) -> None:
        self.source = source
        self.problems = problems
        super().__init__(f"{source}:\n" + "\n".join(f"  - {p}" for p in problems))


class Domain(StrEnum):
    ENTERPRISE = "enterprise"
    FINANCE = "finance"
    SOC = "soc"


class Split(StrEnum):
    PUBLIC = "public"
    VALIDATION = "validation"


class AttackFamily(StrEnum):
    NONE = "none"
    DIRECT_INSTRUCTION = "direct_instruction"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    CONTEXT_AWARE_INJECTION = "context_aware_injection"
    MULTI_STEP = "multi_step"
    MEMORY_POISONING = "memory_poisoning"
    TOOL_OUTPUT_MANIPULATION = "tool_output_manipulation"
    UNAUTHORIZED_CAPABILITY = "unauthorized_capability"
    DATA_EXFILTRATION = "data_exfiltration"
    GOAL_HIJACKING = "goal_hijacking"
    MONITOR_EVASION = "monitor_evasion"


class SurfaceKind(StrEnum):
    EMAIL = "email"
    DOCUMENT = "document"
    WIKI = "wiki"
    TICKET = "ticket"
    CASE_DOCUMENT = "case_document"
    LOG = "log"
    INTEL = "intel"
    ALERT = "alert"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"


class MutationOperation(StrEnum):
    REPLACE_TEXT = "replace_text"
    APPEND_TEXT = "append_text"
    SET_TOOL_TEXT = "set_tool_text"
    WRITE_MEMORY = "write_memory"


SURFACE_OPERATIONS: dict[SurfaceKind, frozenset[MutationOperation]] = {
    SurfaceKind.TOOL_OUTPUT: frozenset({MutationOperation.SET_TOOL_TEXT}),
    SurfaceKind.MEMORY: frozenset({MutationOperation.WRITE_MEMORY}),
}
TEXT_OPERATIONS = frozenset({MutationOperation.REPLACE_TEXT, MutationOperation.APPEND_TEXT})


class SecurityProperty(StrEnum):
    NO_UNAUTHORIZED_TOOL = "no_unauthorized_tool"
    CONSEQUENTIAL_REQUIRES_CONFIRMATION = "consequential_requires_confirmation"
    NO_SENSITIVE_DATA_TO_UNTRUSTED_SINK = "no_sensitive_data_to_untrusted_sink"
    NO_FORBIDDEN_EFFECT = "no_forbidden_effect"
    TOOL_PREREQUISITES = "tool_prerequisites"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PlanStep(_Strict):
    """One step of the evaluator-only reference plan (ground truth for legitimate behavior)."""

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    action: Literal["tool_call", "respond", "memory_write"]
    tool: str | None = None
    args: dict[str, ArgValue] = Field(default_factory=dict)
    content: str | None = None
    match_keys: list[str] | None = None
    confirm: bool = False
    final: bool = False

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.action == "tool_call" and not self.tool:
            raise ValueError(f"plan step {self.id!r}: tool_call requires 'tool'")
        if self.action in ("respond", "memory_write") and self.content is None:
            raise ValueError(f"plan step {self.id!r}: {self.action} requires 'content'")
        if self.confirm and self.action != "tool_call":
            raise ValueError(f"plan step {self.id!r}: only tool calls can require confirmation")
        if self.match_keys is not None:
            unknown = set(self.match_keys) - set(self.args)
            if unknown:
                raise ValueError(f"plan step {self.id!r}: match_keys not in args: {sorted(unknown)}")
        return self


class Turn(_Strict):
    goal: str = Field(min_length=1, max_length=4_000)
    reference_plan: list[PlanStep] = Field(min_length=1, max_length=40)

    @model_validator(mode="after")
    def _unique_ids_and_final(self) -> Self:
        ids = [step.id for step in self.reference_plan]
        if len(ids) != len(set(ids)):
            raise ValueError("reference_plan step ids must be unique within a turn")
        if not self.reference_plan[-1].final:
            raise ValueError("the last reference_plan step must be a final respond step")
        return self


class Surface(_Strict):
    id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,47}$")
    kind: SurfaceKind
    target: str = Field(pattern=TARGET_PATTERN)
    operations: list[MutationOperation] = Field(min_length=1)
    max_chars: int = Field(default=1_500, ge=1, le=8_000)

    @model_validator(mode="after")
    def _operations_fit_kind(self) -> Self:
        allowed = SURFACE_OPERATIONS.get(self.kind, TEXT_OPERATIONS)
        bad = [op.value for op in self.operations if op not in allowed]
        if bad:
            raise ValueError(
                f"surface {self.id!r} ({self.kind}) does not support {bad}; allowed: {sorted(o.value for o in allowed)}"
            )
        prefix = self.target.split("/", 1)[0]
        if self.kind is SurfaceKind.TOOL_OUTPUT and prefix != "tool_output":
            raise ValueError(f"surface {self.id!r}: tool_output targets start with 'tool_output/'")
        if self.kind is SurfaceKind.MEMORY and prefix != "memory":
            raise ValueError(f"surface {self.id!r}: memory targets start with 'memory/'")
        return self


class Payload(_Strict):
    surface: str
    operation: MutationOperation
    text: str = Field(min_length=1, max_length=8_000)


class AttackSpec(_Strict):
    present: bool = False
    family: AttackFamily = AttackFamily.NONE
    difficulty: int = Field(default=1, ge=1, le=5)
    objective: str = ""
    surfaces: list[Surface] = Field(default_factory=list)
    payloads: list[Payload] = Field(default_factory=list)
    max_mutations: int = Field(default=3, ge=0, le=20)
    share_payloads_with_attacker: bool = True

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if not self.present:
            if self.family is not AttackFamily.NONE or self.surfaces or self.payloads:
                raise ValueError("attack.present is false but attack details were given")
            return self
        if self.family is AttackFamily.NONE:
            raise ValueError("attack.present is true: set attack.family")
        if not self.objective:
            raise ValueError("attack.present is true: describe attack.objective")
        surface_ids = [s.id for s in self.surfaces]
        if len(surface_ids) != len(set(surface_ids)):
            raise ValueError("attack surface ids must be unique")
        by_id = {s.id: s for s in self.surfaces}
        for i, payload in enumerate(self.payloads):
            surface = by_id.get(payload.surface)
            if surface is None:
                raise ValueError(f"attack.payloads[{i}] references unknown surface {payload.surface!r}")
            if payload.operation not in surface.operations:
                raise ValueError(f"attack.payloads[{i}]: operation {payload.operation} not allowed on {surface.id!r}")
            if len(payload.text) > surface.max_chars:
                raise ValueError(f"attack.payloads[{i}] exceeds surface max_chars={surface.max_chars}")
        if self.family is not AttackFamily.DIRECT_INSTRUCTION and not self.surfaces:
            raise ValueError("indirect attacks must declare at least one mutation surface")
        return self


class CanarySpec(_Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,47}$")
    kind: Literal["secret_token", "account_id", "access_token", "contract_ref"]
    sensitivity: Sensitivity = Sensitivity.RESTRICTED
    allowed_destinations: list[TrustLevel] = Field(default_factory=list)


class TaskParameterConstraintSpec(_Strict):
    field: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    allowed_values: list[str] = Field(min_length=1)


class TaskGrantSpec(_Strict):
    """Structured task authority supplied by the authenticated runtime boundary."""

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    capabilities: list[str] = Field(min_length=1)
    resources: list[str] = Field(default_factory=list)
    destinations: list[str] = Field(default_factory=list)
    max_amount: float | None = Field(default=None, gt=0)
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    parameters: list[TaskParameterConstraintSpec] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if (self.max_amount is None) != (self.currency is None):
            raise ValueError("task grant max_amount and currency must be set together")
        if len(self.capabilities) != len(set(self.capabilities)):
            raise ValueError("task grant capabilities contain duplicates")
        return self


class TaskAuthorizationSpec(_Strict):
    """Authenticated authority; deliberately contains no scenario/evaluator metadata."""

    task_id: str = Field(pattern=r"^tsk_[a-f0-9]{16}$")
    principal_id: str = Field(min_length=1, max_length=128)
    role: str = Field(min_length=1, max_length=64)
    authenticated_by: str = Field(min_length=1, max_length=128)
    approval_roles: list[str] = Field(default_factory=list)
    delegation_roles: list[str] = Field(default_factory=list)
    grants: list[TaskGrantSpec] = Field(min_length=1)

    @model_validator(mode="after")
    def _protected_authority(self) -> Self:
        if self.authenticated_by.strip().lower() in {"agent", "memory", "model", "message_text"}:
            raise ValueError("task authorization must come from a protected runtime authenticator")
        tools = [grant.tool for grant in self.grants]
        if len(tools) != len(set(tools)):
            raise ValueError("task authorization contains duplicate tool grants")
        return self


# ---- success conditions (state-based graders) -------------------------------------------------


class ResponseContains(_Strict):
    type: Literal["response_contains"]
    facts: list[str] = Field(min_length=1)
    turn: int | None = None


class RecordExists(_Strict):
    type: Literal["record_exists"]
    collection: str
    where: dict[str, ArgValue] = Field(default_factory=dict)


class RecordFieldEquals(_Strict):
    type: Literal["record_field_equals"]
    collection: str
    where: dict[str, ArgValue] = Field(default_factory=dict)
    field: str
    value: ArgValue


class RecordFieldContains(_Strict):
    type: Literal["record_field_contains"]
    collection: str
    where: dict[str, ArgValue] = Field(default_factory=dict)
    field: str
    facts: list[str] = Field(min_length=1)


class NoEffect(_Strict):
    type: Literal["no_effect"]
    effect: str


class CustomCondition(_Strict):
    """Extension point: a grader registered in sentinel.evaluator.task_graders by name."""

    type: Literal["custom"]
    grader: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    params: dict[str, ArgValue] = Field(default_factory=dict)


SuccessCondition = Annotated[
    ResponseContains | RecordExists | RecordFieldEquals | RecordFieldContains | NoEffect | CustomCondition,
    Field(discriminator="type"),
]


class Scenario(_Strict):
    id: str = Field(pattern=ID_PATTERN)
    version: int = Field(ge=1)
    seed: int = Field(ge=0, le=2**31 - 1)
    domain: Domain
    split: Split
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2_000)
    tags: list[str] = Field(default_factory=list)
    policy_profile: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    task_authorization: TaskAuthorizationSpec | None = None
    fixture: str
    extra_records: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    allowed_tools: list[str] = Field(min_length=1)
    max_steps: int = Field(default=30, ge=1, le=200)
    turns: list[Turn] = Field(min_length=1, max_length=5)
    attack: AttackSpec = Field(default_factory=AttackSpec)
    success_conditions: list[SuccessCondition] = Field(min_length=1)
    security_properties: list[SecurityProperty] = Field(default_factory=list)
    forbidden_effects: list[str] = Field(default_factory=list)
    canaries: list[CanarySpec] = Field(default_factory=list)

    @model_validator(mode="after")
    def _cross_checks(self) -> Self:
        fixture = Path(self.fixture)
        if _is_absolute_on_any_supported_platform(self.fixture) or ".." in fixture.parts:
            raise ValueError("fixture must be a relative path inside the benchmark root (no '..')")
        if not self.fixture.endswith(".json"):
            raise ValueError("fixture must be a .json file")
        if len(set(self.allowed_tools)) != len(self.allowed_tools):
            raise ValueError("allowed_tools contains duplicates")
        if self.task_authorization is not None:
            unauthorized = sorted({grant.tool for grant in self.task_authorization.grants} - set(self.allowed_tools))
            if unauthorized:
                raise ValueError(f"task authorization grants tools outside allowed_tools: {unauthorized}")
        for t_index, turn in enumerate(self.turns):
            for step in turn.reference_plan:
                if step.tool and step.tool not in self.allowed_tools:
                    raise ValueError(
                        f"turns[{t_index}] step {step.id!r} uses {step.tool!r} which is not in allowed_tools"
                    )
        if self.attack.present and not self.security_properties:
            raise ValueError("attack scenarios must list security_properties to check")
        names = [c.name for c in self.canaries]
        if len(names) != len(set(names)):
            raise ValueError("canary names must be unique")
        return self

    @property
    def is_benign(self) -> bool:
        return not self.attack.present

    @property
    def is_hard_negative(self) -> bool:
        return "hard_negative" in self.tags


# ---- loading ----------------------------------------------------------------------------------


def _format_validation_error(exc: ValidationError) -> list[str]:
    problems = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<root>"
        message = error["msg"].removeprefix("Value error, ")
        problems.append(f"{location}: {message}")
    return problems


def parse_scenario(data: Any, source: str = "<memory>") -> Scenario:
    if not isinstance(data, dict):
        raise ScenarioError(source, ["top level must be a mapping"])
    try:
        return Scenario.model_validate(data)
    except ValidationError as exc:
        raise ScenarioError(source, _format_validation_error(exc)) from exc


def load_scenario(path: Path) -> Scenario:
    """Load a scenario with yaml.safe_load only: no Python object constructors are honored."""
    source = str(path)
    if path.suffix not in (".yaml", ".yml", ".json"):
        raise ScenarioError(source, ["scenario files must be .yaml, .yml, or .json"])
    raw = path.read_bytes()
    if len(raw) > MAX_SCENARIO_BYTES:
        raise ScenarioError(source, [f"file exceeds {MAX_SCENARIO_BYTES} bytes"])
    try:
        data = json.loads(raw) if path.suffix == ".json" else yaml.safe_load(raw)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ScenarioError(source, [f"could not parse file: {exc}"]) from exc
    return parse_scenario(data, source)


def discover_scenarios(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    files = sorted(p for p in path.rglob("*") if p.suffix in (".yaml", ".yml") and p.is_file())
    return [p for p in files if "schemas" not in p.parts]


def scenario_json_schema() -> dict[str, Any]:
    return Scenario.model_json_schema()


# ---- seeded randomness ------------------------------------------------------------------------


def child_seed(seed: int, *labels: str | int) -> int:
    material = ":".join([str(seed), *(str(label) for label in labels)])
    return int.from_bytes(hashlib.sha256(material.encode()).digest()[:8], "big")


def child_rng(seed: int, *labels: str | int) -> random.Random:
    """All simulator randomness must come from a child RNG of the scenario seed."""
    return random.Random(child_seed(seed, *labels))
