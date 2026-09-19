"""Versioned strict ToolSpecs for every organizer-provided simulator tool."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinel.core.provenance import TrustLevel
from sentinel.firewall.records import DataSensitivity
from sentinel.tools.base import Tool
from sentinel.tools.registry import registry_for_domain

TOOL_SPEC_VERSION = "1.0.0"
NORMALIZER_VERSION = "sentinel-c14n/1"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EffectClass(StrEnum):
    READ = "read"
    DRAFT = "draft"
    WRITE = "write"
    MESSAGE = "message"
    STATE_CHANGE = "state_change"


class ApprovalRule(StrEnum):
    NEVER = "never"
    ALWAYS = "always"
    CONDITIONAL = "conditional"


class LifecycleRule(StrEnum):
    NONE = "none"
    PAYMENT_PREPARE = "payment_prepare"
    PAYMENT_CONFIRM = "payment_confirm"
    PAYMENT_EXECUTE = "payment_execute"
    REMEDIATION_PREPARE = "remediation_prepare"
    REMEDIATION_EXECUTE = "remediation_execute"
    TICKET_UPDATE = "ticket_update"
    INCIDENT_UPDATE = "incident_update"


class OutputLabelStrategy(StrEnum):
    RECORD_METADATA = "record_metadata"
    RUNTIME_GENERATED = "runtime_generated"


class ToolSpec(_Frozen):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    version: str = TOOL_SPEC_VERSION
    strict_schema_json: str
    capabilities: tuple[str, ...]
    effect_class: EffectClass
    read_scopes: tuple[str, ...] = ()
    write_scopes: tuple[str, ...] = ()
    resource_fields: tuple[str, ...] = ()
    payload_fields: tuple[str, ...] = ()
    destination_fields: tuple[str, ...] = ()
    amount_fields: tuple[str, ...] = ()
    lifecycle_rule: LifecycleRule = LifecycleRule.NONE
    approval_rule: ApprovalRule = ApprovalRule.NEVER
    approval_field: str | None = None
    approval_values: tuple[str, ...] = ()
    output_label_strategy: OutputLabelStrategy
    fallback_output_trust: TrustLevel
    fallback_output_sensitivity: DataSensitivity
    destination_restricted_output_fields: tuple[str, ...] = ()
    normalizer_version: str = NORMALIZER_VERSION

    @model_validator(mode="after")
    def _valid_schema_and_approval(self) -> ToolSpec:
        schema = json.loads(self.strict_schema_json)
        if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
            raise ValueError("ToolSpec schemas must be strict objects")
        if self.approval_rule is ApprovalRule.CONDITIONAL:
            if self.approval_field is None or not self.approval_values:
                raise ValueError("conditional approval requires a field and values")
        elif self.approval_field is not None or self.approval_values:
            raise ValueError("approval field/values are only valid for conditional approval")
        return self

    @property
    def strict_schema(self) -> dict[str, Any]:
        parsed = json.loads(self.strict_schema_json)
        if not isinstance(parsed, dict):
            raise ValueError("ToolSpec schema is not an object")
        return parsed


class ToolManifest(_Frozen):
    version: str = TOOL_SPEC_VERSION
    normalizer_version: str = NORMALIZER_VERSION
    specs: tuple[ToolSpec, ...]
    manifest_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def _unique_and_hashed(self) -> ToolManifest:
        names = [spec.name for spec in self.specs]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("ToolSpecs must be unique and sorted by name")
        expected = _manifest_hash(self.specs)
        if self.manifest_hash != expected:
            raise ValueError("manifest hash does not match ToolSpecs")
        return self

    def get(self, name: str) -> ToolSpec | None:
        return next((spec for spec in self.specs if spec.name == name), None)


class _Overlay(_Frozen):
    effect_class: EffectClass
    read_scopes: tuple[str, ...] = ()
    write_scopes: tuple[str, ...] = ()
    resource_fields: tuple[str, ...] = ()
    payload_fields: tuple[str, ...] = ()
    destination_fields: tuple[str, ...] = ()
    amount_fields: tuple[str, ...] = ()
    lifecycle_rule: LifecycleRule = LifecycleRule.NONE
    approval_rule: ApprovalRule = ApprovalRule.NEVER
    approval_field: str | None = None
    approval_values: tuple[str, ...] = ()
    output_label_strategy: OutputLabelStrategy = OutputLabelStrategy.RECORD_METADATA
    fallback_output_trust: TrustLevel = TrustLevel.UNTRUSTED_EXTERNAL
    fallback_output_sensitivity: DataSensitivity = DataSensitivity.UNKNOWN
    destination_restricted_output_fields: tuple[str, ...] = ()


def _read(scope: str, *resources: str) -> _Overlay:
    return _Overlay(effect_class=EffectClass.READ, read_scopes=(scope,), resource_fields=resources)


def _generated(
    effect: EffectClass,
    scope: str,
    *,
    resources: tuple[str, ...] = (),
    payload: tuple[str, ...] = (),
    destinations: tuple[str, ...] = (),
    amounts: tuple[str, ...] = (),
    lifecycle: LifecycleRule = LifecycleRule.NONE,
    approval: ApprovalRule = ApprovalRule.NEVER,
    approval_field: str | None = None,
    approval_values: tuple[str, ...] = (),
    sensitivity: DataSensitivity = DataSensitivity.INTERNAL,
) -> _Overlay:
    return _Overlay(
        effect_class=effect,
        write_scopes=(scope,),
        resource_fields=resources,
        payload_fields=payload,
        destination_fields=destinations,
        amount_fields=amounts,
        lifecycle_rule=lifecycle,
        approval_rule=approval,
        approval_field=approval_field,
        approval_values=approval_values,
        output_label_strategy=OutputLabelStrategy.RUNTIME_GENERATED,
        fallback_output_trust=TrustLevel.TRUSTED_INTERNAL,
        fallback_output_sensitivity=sensitivity,
    )


_OVERLAYS: dict[str, _Overlay] = {
    # Enterprise
    "email_search": _read("mailbox"),
    "email_read": _read("mailbox", "email_id"),
    "email_draft": _generated(
        EffectClass.DRAFT,
        "email_drafts",
        payload=("subject", "body"),
        destinations=("to",),
    ),
    "email_send": _generated(
        EffectClass.MESSAGE,
        "email_outbox",
        payload=("subject", "body"),
        destinations=("to",),
        approval=ApprovalRule.ALWAYS,
    ),
    "document_search": _read("documents"),
    "document_read": _read("documents", "doc_id"),
    "wiki_search": _read("wiki"),
    "ticket_read": _read("tickets", "ticket_id"),
    "ticket_update": _generated(
        EffectClass.WRITE,
        "tickets",
        resources=("ticket_id",),
        payload=("note",),
        destinations=("ticket_id",),
        lifecycle=LifecycleRule.TICKET_UPDATE,
        approval=ApprovalRule.CONDITIONAL,
        approval_field="status",
        approval_values=("resolved", "closed"),
    ),
    # Finance
    "customer_lookup": _read("customers", "customer_id"),
    "account_summary": _read("accounts", "account_id"),
    "case_document_read": _read("case_documents", "case_id", "doc_id"),
    "case_note_create": _generated(
        EffectClass.WRITE,
        "case_notes",
        resources=("case_id",),
        payload=("text",),
        destinations=("case_id",),
        sensitivity=DataSensitivity.CONFIDENTIAL,
    ),
    "policy_search": _read("policies"),
    "payment_prepare": _generated(
        EffectClass.WRITE,
        "payments",
        resources=("account_id", "beneficiary_id"),
        payload=("reference",),
        destinations=("beneficiary_id",),
        amounts=("amount",),
        lifecycle=LifecycleRule.PAYMENT_PREPARE,
        sensitivity=DataSensitivity.CONFIDENTIAL,
    ),
    "payment_confirm": _generated(
        EffectClass.STATE_CHANGE,
        "payments",
        resources=("payment_id",),
        lifecycle=LifecycleRule.PAYMENT_CONFIRM,
        approval=ApprovalRule.ALWAYS,
        sensitivity=DataSensitivity.CONFIDENTIAL,
    ),
    "payment_execute": _generated(
        EffectClass.STATE_CHANGE,
        "payments",
        resources=("payment_id",),
        lifecycle=LifecycleRule.PAYMENT_EXECUTE,
        approval=ApprovalRule.ALWAYS,
        sensitivity=DataSensitivity.CONFIDENTIAL,
    ),
    # SOC
    "alert_search": _read("alerts"),
    "alert_read": _read("alerts", "alert_id"),
    "asset_lookup": _read("assets", "asset_id").model_copy(
        update={"destination_restricted_output_fields": ("service_account_token",)}
    ),
    "intel_search": _read("intel"),
    "incident_create": _generated(
        EffectClass.WRITE,
        "incidents",
        resources=("alert_id",),
        payload=("title", "summary"),
        destinations=("alert_id",),
    ),
    "incident_update": _generated(
        EffectClass.WRITE,
        "incidents",
        resources=("incident_id",),
        payload=("note",),
        destinations=("incident_id",),
        lifecycle=LifecycleRule.INCIDENT_UPDATE,
        approval=ApprovalRule.CONDITIONAL,
        approval_field="status",
        approval_values=("closed",),
    ),
    "remediation_prepare": _generated(
        EffectClass.WRITE,
        "remediations",
        resources=("asset_id",),
        payload=("justification",),
        destinations=("asset_id",),
        lifecycle=LifecycleRule.REMEDIATION_PREPARE,
    ),
    "remediation_execute": _generated(
        EffectClass.STATE_CHANGE,
        "remediations",
        resources=("remediation_id",),
        lifecycle=LifecycleRule.REMEDIATION_EXECUTE,
        approval=ApprovalRule.ALWAYS,
    ),
}


def _schema_json(tool: Tool) -> str:
    schema = tool.args_model.model_json_schema()
    return json.dumps(schema, sort_keys=True, separators=(",", ":"))


def _manifest_hash(specs: tuple[ToolSpec, ...]) -> str:
    payload = [
        spec.model_dump(mode="json", exclude={"strict_schema_json"}) | {"schema": spec.strict_schema} for spec in specs
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def build_tool_manifest(tools: tuple[Tool, ...]) -> ToolManifest:
    """Build a strict manifest and fail if any registered tool lacks trusted semantics."""
    names = [tool.name for tool in tools]
    if len(names) != len(set(names)):
        raise ValueError("duplicate tools cannot be manifested")
    missing = sorted(set(names) - set(_OVERLAYS))
    unexpected = sorted(set(_OVERLAYS) - set(names))
    if missing or unexpected:
        raise ValueError(f"ToolSpec coverage mismatch: missing={missing}, unexpected={unexpected}")
    specs = tuple(
        ToolSpec(
            name=tool.name,
            strict_schema_json=_schema_json(tool),
            capabilities=tuple(sorted(tool.capabilities)),
            **_OVERLAYS[tool.name].model_dump(),
        )
        for tool in sorted(tools, key=lambda item: item.name)
    )
    return ToolManifest(specs=specs, manifest_hash=_manifest_hash(specs))


def build_official_tool_manifest() -> ToolManifest:
    tools = tuple(tool for domain in ("enterprise", "finance", "soc") for tool in registry_for_domain(domain))
    return build_tool_manifest(tools)
