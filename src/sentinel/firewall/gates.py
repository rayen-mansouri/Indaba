"""Deterministic G1-G7 evaluation over trusted runtime records."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from sentinel.core.actions import ActionType, Decision
from sentinel.core.provenance import TrustLevel
from sentinel.firewall.approvals import ApprovalStatus, ApprovalStore
from sentinel.firewall.normalization import DestinationMap
from sentinel.firewall.policy import PolicySnapshot
from sentinel.firewall.records import DataSensitivity, DecisionContext
from sentinel.firewall.toolspecs import ApprovalRule, LifecycleRule, ToolManifest, ToolSpec


class GateName(StrEnum):
    G1_EFFECT_AUTHORIZATION = "G1"
    G2_TASK_SCOPE = "G2"
    G3_LIFECYCLE = "G3"
    G4_APPROVAL = "G4"
    G5_MEMORY_AUTHORITY = "G5"
    G6_CONFIDENTIALITY = "G6"
    G7_DESTINATION = "G7"


class GateResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    gate: GateName
    applicable: bool
    passed: bool
    reason_codes: tuple[str, ...] = ()
    risk_basis: tuple[str, ...] = ()


class GateEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: Decision
    risk_score: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    reason_codes: tuple[str, ...]
    gate_results: tuple[GateResult, ...]


_APPROVAL_REASONS = {
    ApprovalStatus.MISSING: "APPROVAL_REQUIRED",
    ApprovalStatus.MISMATCH: "APPROVAL_MISMATCH",
    ApprovalStatus.DENIED: "APPROVAL_DENIED",
    ApprovalStatus.EXPIRED: "APPROVAL_EXPIRED",
    ApprovalStatus.STALE_STATE: "APPROVAL_STALE_STATE",
    ApprovalStatus.STALE_POLICY: "APPROVAL_STALE_POLICY",
    ApprovalStatus.INVALID_ROLE: "APPROVAL_INVALID_ROLE",
    ApprovalStatus.REPLAYED: "APPROVAL_REPLAYED",
}


class GateEvaluator:
    def __init__(
        self,
        manifest: ToolManifest,
        policy: PolicySnapshot,
        approvals: ApprovalStore,
        destinations: DestinationMap,
    ) -> None:
        if policy.manifest_hash != manifest.manifest_hash:
            raise ValueError("policy snapshot is bound to another ToolSpec manifest")
        self.manifest = manifest
        self.policy = policy
        self.approvals = approvals
        self.destinations = destinations

    def evaluate(self, context: DecisionContext, now: datetime) -> GateEvaluation:
        action = context.candidate.executable
        spec = self.manifest.get(action.tool or "") if action.type is ActionType.TOOL_CALL else None
        results = (
            self._g1(context, spec),
            self._g2(context, spec),
            self._g3(context, spec),
            self._g4(context, spec, now),
            self._g5(context),
            self._g6(context, spec),
            self._g7(context, spec),
        )
        failures = [result for result in results if result.applicable and not result.passed]
        only_missing_approval = bool(failures) and all(
            result.gate is GateName.G4_APPROVAL and result.reason_codes == ("APPROVAL_REQUIRED",) for result in failures
        )
        if only_missing_approval:
            outcome, risk, confidence = Decision.ESCALATE, 0.65, 1.0
        elif failures:
            outcome, risk, confidence = Decision.BLOCK, 0.95, 1.0
        else:
            outcome, risk, confidence = Decision.ALLOW, 0.05, 1.0
        codes = tuple(dict.fromkeys(code for result in failures for code in result.reason_codes))
        return GateEvaluation(
            outcome=outcome,
            risk_score=risk,
            confidence=confidence,
            reason_codes=codes or ("POLICY_CHECKS_PASSED",),
            gate_results=results,
        )

    def _g1(self, context: DecisionContext, spec: ToolSpec | None) -> GateResult:
        if spec is None or spec.effect_class.value == "read":
            return GateResult(gate=GateName.G1_EFFECT_AUTHORIZATION, applicable=False, passed=True)
        grant = context.task_scope.grant_for(spec.name)
        if grant is None:
            return GateResult(
                gate=GateName.G1_EFFECT_AUTHORIZATION,
                applicable=True,
                passed=False,
                reason_codes=("NO_TRUSTED_EFFECT_AUTHORITY",),
                risk_basis=("task scope has no effect grant",),
            )
        return GateResult(
            gate=GateName.G1_EFFECT_AUTHORIZATION,
            applicable=True,
            passed=True,
            risk_basis=("authority=authenticated_task_scope",),
        )

    def _g2(self, context: DecisionContext, spec: ToolSpec | None) -> GateResult:
        action = context.candidate.executable
        if action.type is ActionType.TOOL_CALL and spec is None:
            return GateResult(
                gate=GateName.G2_TASK_SCOPE,
                applicable=True,
                passed=False,
                reason_codes=("UNKNOWN_TOOL",),
            )
        if spec is None:
            return GateResult(gate=GateName.G2_TASK_SCOPE, applicable=False, passed=True)
        grant = context.task_scope.grant_for(spec.name)
        codes: list[str] = []
        if (
            context.run_id != self.policy.run_id
            or context.active_policy_hash != self.policy.policy_hash
            or context.candidate.normalizer_version != self.manifest.normalizer_version
            or context.candidate.tool_spec_version != spec.version
        ):
            codes.append("MALFORMED_SECURITY_METADATA")
        if spec.name not in self.policy.allowed_tools:
            codes.append("POLICY_TOOL_DENIED")
        if grant is None:
            codes.append("TASK_CAPABILITY_DENIED")
        else:
            if not set(spec.capabilities).issubset(grant.capabilities):
                codes.append("TASK_CAPABILITY_DENIED")
            resources = [str(action.arguments[field]) for field in spec.resource_fields if field in action.arguments]
            if resources and (not grant.resources or any(value not in grant.resources for value in resources)):
                codes.append("TASK_RESOURCE_DENIED")
            amounts = [
                float(value)
                for field in spec.amount_fields
                if isinstance((value := action.arguments.get(field)), int | float) and not isinstance(value, bool)
            ]
            if amounts and (grant.max_amount is None or any(value > grant.max_amount for value in amounts)):
                codes.append("TASK_AMOUNT_DENIED")
            for constraint in grant.parameters:
                value = action.arguments.get(constraint.field)
                if value is not None and str(value) not in constraint.allowed_values:
                    codes.append("TASK_PARAMETER_DENIED")
        return GateResult(
            gate=GateName.G2_TASK_SCOPE,
            applicable=True,
            passed=not codes,
            reason_codes=tuple(dict.fromkeys(codes)),
        )

    def _g3(self, context: DecisionContext, spec: ToolSpec | None) -> GateResult:
        if spec is None or spec.lifecycle_rule is LifecycleRule.NONE:
            return GateResult(gate=GateName.G3_LIFECYCLE, applicable=False, passed=True)
        action = context.candidate.executable
        required: str | None = None
        field: str | None = None
        prerequisite: str | None = None
        if spec.lifecycle_rule is LifecycleRule.PAYMENT_CONFIRM:
            field, required, prerequisite = "payment_id", "prepared", "payment_prepare"
        elif spec.lifecycle_rule is LifecycleRule.PAYMENT_EXECUTE:
            field, required, prerequisite = "payment_id", "confirmed", "payment_confirm"
        elif spec.lifecycle_rule is LifecycleRule.REMEDIATION_EXECUTE:
            field, required, prerequisite = "remediation_id", "prepared", "remediation_prepare"
        if field is None:
            return GateResult(gate=GateName.G3_LIFECYCLE, applicable=True, passed=True)
        resource = str(action.arguments.get(field, ""))
        lifecycle = context.live_agent_state.lifecycle_for(resource)
        passed = lifecycle == required and (
            prerequisite is None or prerequisite in context.live_agent_state.succeeded_tools
        )
        return GateResult(
            gate=GateName.G3_LIFECYCLE,
            applicable=True,
            passed=passed,
            reason_codes=() if passed else ("LIFECYCLE_MISMATCH",),
            risk_basis=(f"{resource}:{lifecycle or 'missing'} expected={required}",),
        )

    @staticmethod
    def _approval_applies(spec: ToolSpec, arguments: Mapping[str, object]) -> bool:
        if spec.approval_rule is ApprovalRule.ALWAYS:
            return True
        if spec.approval_rule is ApprovalRule.CONDITIONAL and spec.approval_field:
            return str(arguments.get(spec.approval_field)) in spec.approval_values
        return False

    def _g4(self, context: DecisionContext, spec: ToolSpec | None, now: datetime) -> GateResult:
        if spec is None or not self._approval_applies(spec, context.candidate.executable.arguments):
            return GateResult(gate=GateName.G4_APPROVAL, applicable=False, passed=True)
        status = self.approvals.status(
            task_id=context.task_scope.task_id,
            action_digest=context.candidate.action_digest,
            policy_version=self.policy.policy_version,
            policy_hash=self.policy.policy_hash,
            state_version=context.live_agent_state.version,
            allowed_roles=context.task_scope.approval_roles,
            now=now,
        )
        return GateResult(
            gate=GateName.G4_APPROVAL,
            applicable=True,
            passed=status is ApprovalStatus.VALID,
            reason_codes=() if status is ApprovalStatus.VALID else (_APPROVAL_REASONS[status],),
            risk_basis=(f"approval={status.value}",),
        )

    def _g5(self, context: DecisionContext) -> GateResult:
        authenticator = context.task_scope.principal.authenticated_by.strip().lower()
        invalid = authenticator in {"agent", "memory", "model", "message_text"}
        return GateResult(
            gate=GateName.G5_MEMORY_AUTHORITY,
            applicable=True,
            passed=not invalid,
            reason_codes=("UNPROTECTED_AUTHORITY_SOURCE",) if invalid else (),
            risk_basis=(f"authenticated_by={authenticator}",),
        )

    def _destination_trust(self, destination: str) -> TrustLevel:
        if "@" in destination:
            domain = destination.rsplit("@", 1)[-1].lower()
            if domain in self.destinations.internal_email_domains:
                return TrustLevel.TRUSTED_INTERNAL
            return TrustLevel.UNTRUSTED_EXTERNAL
        return TrustLevel.TRUSTED_INTERNAL

    def _g6(self, context: DecisionContext, spec: ToolSpec | None) -> GateResult:
        if spec is None or not spec.payload_fields:
            return GateResult(gate=GateName.G6_CONFIDENTIALITY, applicable=False, passed=True)
        payload_fields = tuple(
            field
            for field in spec.payload_fields
            if context.candidate.executable.arguments.get(field) not in (None, "")
        )
        if not payload_fields:
            return GateResult(gate=GateName.G6_CONFIDENTIALITY, applicable=False, passed=True)
        nodes = {node.node_id: node for node in context.provenance}
        destinations = context.candidate.canonical_destinations or ("trusted_internal_sink",)
        codes: list[str] = []
        basis: list[str] = []
        for field in payload_fields:
            dependencies = [nodes[node_id] for node_id in context.candidate.dependencies_for(field)]
            sensitivity = (
                DataSensitivity.UNKNOWN
                if not dependencies or any(node.sensitivity is DataSensitivity.UNKNOWN for node in dependencies)
                else max((node.sensitivity for node in dependencies), key=lambda item: item.rank)
            )
            for destination in destinations:
                trust = self._destination_trust(destination)
                if sensitivity is DataSensitivity.UNKNOWN:
                    codes.append("UNKNOWN_SENSITIVITY")
                elif trust.rank > TrustLevel.TRUSTED_INTERNAL.rank and sensitivity is not DataSensitivity.PUBLIC:
                    codes.append("SENSITIVE_EGRESS")
                if any(node.allowed_destinations and trust not in node.allowed_destinations for node in dependencies):
                    codes.append("DESTINATION_SENSITIVITY_DENIED")
                basis.append(f"{field}:{sensitivity.value}->{trust.value}")
        return GateResult(
            gate=GateName.G6_CONFIDENTIALITY,
            applicable=True,
            passed=not codes,
            reason_codes=tuple(dict.fromkeys(codes)),
            risk_basis=tuple(basis),
        )

    def _g7(self, context: DecisionContext, spec: ToolSpec | None) -> GateResult:
        if spec is None or not spec.destination_fields:
            return GateResult(gate=GateName.G7_DESTINATION, applicable=False, passed=True)
        grant = context.task_scope.grant_for(spec.name)
        allowed = set(grant.destinations) if grant else set()
        mismatched = [
            destination for destination in context.candidate.canonical_destinations if destination not in allowed
        ]
        passed = (
            spec.name in self.policy.allowed_tools and bool(context.candidate.canonical_destinations) and not mismatched
        )
        return GateResult(
            gate=GateName.G7_DESTINATION,
            applicable=True,
            passed=passed,
            reason_codes=() if passed else ("DESTINATION_NOT_AUTHORIZED",),
            risk_basis=tuple(f"destination={value}" for value in context.candidate.canonical_destinations),
        )
