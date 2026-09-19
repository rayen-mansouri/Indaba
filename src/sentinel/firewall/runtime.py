"""Run-bound SENTINEL defense and the only guarded path to the simulator gateway."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sentinel.core.actions import ActionType, CandidateAction, Decision, DefenseDecision
from sentinel.core.events import Actor, EventLog, EventType
from sentinel.core.policies import Policy
from sentinel.core.provenance import Sensitivity, TrustLevel
from sentinel.core.scenario import TaskAuthorizationSpec
from sentinel.core.state import WorldState
from sentinel.defenses.interface import ConversationItem, Defense, DefenseRequest
from sentinel.firewall.approvals import ApprovalDecision, ApprovalStatus, ApprovalStore
from sentinel.firewall.gates import GateEvaluation, GateEvaluator
from sentinel.firewall.normalization import (
    ActionNormalizationError,
    DestinationMap,
    TrustedActionAdapters,
)
from sentinel.firewall.policy import PolicySnapshot
from sentinel.firewall.provenance import ProvenanceGraph, contains_transformed_value, derive_observed_variants
from sentinel.firewall.records import (
    AuthenticatedPrincipal,
    CapabilityGrant,
    DataSensitivity,
    DecisionContext,
    NormalizedAction,
    ObservedContent,
    ParameterConstraint,
    ResourceState,
    TaskScope,
    Transformation,
    WorkflowState,
)
from sentinel.firewall.toolspecs import ApprovalRule, EffectClass, ToolManifest, build_official_tool_manifest
from sentinel.tools.base import ToolOutcome
from sentinel.tools.gateway import GatewayResult, ToolGateway
from sentinel.tools.registry import ToolRegistry

APPROVAL_TTL = timedelta(minutes=5)


@dataclass(frozen=True)
class GuardedPreparation:
    """Opaque one-shot permission to execute one exact normalized action."""

    action: CandidateAction
    action_digest: str
    state_version: int
    permit_id: str | None
    error: str | None = None

    @property
    def permitted(self) -> bool:
        return self.permit_id is not None and self.error is None


@dataclass(frozen=True)
class _Permit:
    permit_id: str
    step_id: int
    action_digest: str
    state_version: int


def _data_sensitivity(value: Sensitivity) -> DataSensitivity:
    return DataSensitivity(value.value)


def _task_scope(authority: TaskAuthorizationSpec) -> TaskScope:
    return TaskScope(
        task_id=authority.task_id,
        principal=AuthenticatedPrincipal(
            principal_id=authority.principal_id,
            role=authority.role,
            authenticated_by=authority.authenticated_by,
        ),
        grants=tuple(
            CapabilityGrant(
                tool=grant.tool,
                capabilities=tuple(grant.capabilities),
                resources=tuple(grant.resources),
                destinations=tuple(grant.destinations),
                max_amount=grant.max_amount,
                currency=grant.currency,
                parameters=tuple(
                    ParameterConstraint(field=item.field, allowed_values=tuple(item.allowed_values))
                    for item in grant.parameters
                ),
            )
            for grant in authority.grants
        ),
        approval_roles=tuple(authority.approval_roles),
        delegation_roles=tuple(authority.delegation_roles),
        issued_state_version=0,
    )


class SentinelFirewallDefense(Defense):
    """Deterministic action firewall. A run must bind trusted state before use."""

    name = "sentinel"

    def __init__(self) -> None:
        self._bound = False
        self._manifest: ToolManifest | None = None
        self._policy: PolicySnapshot | None = None
        self._scope: TaskScope | None = None
        self._registry: ToolRegistry | None = None
        self._state: WorldState | None = None
        self._gateway: ToolGateway | None = None
        self._log: EventLog | None = None
        self._graph: ProvenanceGraph | None = None
        self._adapters: TrustedActionAdapters | None = None
        self._evaluator: GateEvaluator | None = None
        self._approvals = ApprovalStore()
        self._source_ids: dict[str, str] = {}
        self._observed_by_step: dict[int, tuple[ObservedContent, ...]] = {}
        self._decision_actions: dict[int, set[str]] = {}
        self._traced_actions: set[tuple[str, int]] = set()
        self._permits: dict[str, _Permit] = {}
        self._permit_counter = 0
        self._state_version = 0
        self._succeeded_tools: list[str] = []

    def bind_run(
        self,
        *,
        run_id: str,
        task_authorization: TaskAuthorizationSpec,
        policy: Policy,
        allowed_tools: tuple[str, ...],
        registry: ToolRegistry,
        state: WorldState,
        gateway: ToolGateway,
        log: EventLog,
    ) -> None:
        """Bind trusted runtime objects; evaluator labels and scenario records are not accepted."""
        if self._bound:
            raise RuntimeError("a SENTINEL defense instance cannot be rebound")
        manifest = build_official_tool_manifest()
        snapshot = PolicySnapshot.capture(run_id, policy, manifest, allowed_tools)
        scope = _task_scope(task_authorization)
        unknown_grants = sorted({grant.tool for grant in scope.grants} - set(snapshot.allowed_tools))
        if unknown_grants:
            raise ValueError(f"task scope grants tools outside active policy: {unknown_grants}")
        internal_domain = state.settings.get("internal_email_domain")
        destinations = DestinationMap(
            internal_email_domains=(str(internal_domain).lower(),) if internal_domain else (),
        )
        session_material = f"{run_id}:{scope.task_id}:{manifest.manifest_hash}".encode()
        session_id = "session_" + hashlib.sha256(session_material).hexdigest()[:24]
        self._manifest = manifest
        self._policy = snapshot
        self._scope = scope
        self._registry = registry
        self._state = state
        self._gateway = gateway
        self._log = log
        self._graph = ProvenanceGraph(run_id, session_id)
        self._adapters = TrustedActionAdapters(tuple(registry), manifest, destinations)
        self._evaluator = GateEvaluator(manifest, snapshot, self._approvals, destinations)
        self._bound = True

    # ---- trusted context construction -----------------------------------------------------
    def _require_bound(
        self,
    ) -> tuple[
        ToolManifest,
        PolicySnapshot,
        TaskScope,
        WorldState,
        ProvenanceGraph,
        TrustedActionAdapters,
        GateEvaluator,
    ]:
        if not self._bound:
            raise RuntimeError("SENTINEL runtime is not bound")
        assert self._manifest is not None
        assert self._policy is not None
        assert self._scope is not None
        assert self._state is not None
        assert self._graph is not None
        assert self._adapters is not None
        assert self._evaluator is not None
        return (
            self._manifest,
            self._policy,
            self._scope,
            self._state,
            self._graph,
            self._adapters,
            self._evaluator,
        )

    def _canary_security(
        self, text: str, default: DataSensitivity
    ) -> tuple[DataSensitivity, tuple[TrustLevel, ...], bool]:
        assert self._state is not None
        matches = [canary for canary in self._state.canaries if contains_transformed_value(text, canary.value)]
        if not matches:
            return default, (), False
        sensitivity = max(
            [default, *(_data_sensitivity(canary.sensitivity) for canary in matches)],
            key=lambda item: item.rank,
        )
        allowed_sets = [set(canary.allowed_destinations) for canary in matches]
        allowed = set.intersection(*allowed_sets) if allowed_sets else set()
        return sensitivity, tuple(sorted(allowed, key=lambda item: item.rank)), True

    def _import_provenance(self, request: DefenseRequest) -> None:
        _, _, _, _, graph, _, _ = self._require_bound()
        for record in request.provenance:
            if record.id in self._source_ids:
                continue
            default = _data_sensitivity(record.provenance.sensitivity)
            node = graph.import_provenance(
                record.provenance,
                sensitivity=default,
            )
            self._source_ids[record.id] = node.node_id

    @staticmethod
    def _fallback_source(item: ConversationItem) -> tuple[TrustLevel, DataSensitivity, bool]:
        if item.role == "user":
            return TrustLevel.AUTHENTICATED_USER, DataSensitivity.INTERNAL, False
        if item.role in {"human", "safety", "tool"}:
            return TrustLevel.TRUSTED_INTERNAL, DataSensitivity.INTERNAL, False
        return TrustLevel.ADVERSARY_CONTROLLED, DataSensitivity.UNKNOWN, True

    @staticmethod
    def _structured_fields(value: object, path: str = "") -> list[tuple[str, str]]:
        fields: list[tuple[str, str]] = []
        if isinstance(value, dict):
            for key, item in value.items():
                child = f"{path}.{key}" if path else str(key)
                fields.extend(SentinelFirewallDefense._structured_fields(item, child))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                child = f"{path}[{index}]"
                fields.extend(SentinelFirewallDefense._structured_fields(item, child))
        elif value is not None:
            rendered = str(value).lower() if isinstance(value, bool) else str(value)
            fields.append((path or "value", rendered))
        return fields

    def _field_observations(
        self,
        content: str,
        parent_ids: tuple[str, ...],
    ) -> tuple[ObservedContent, ...]:
        _, _, _, _, graph, _, _ = self._require_bound()
        try:
            parsed = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        fields = self._structured_fields(parsed) if isinstance(parsed, dict | list) else []
        if not fields:
            _, allowed, restricted = self._canary_security(content, DataSensitivity.INTERNAL)
            if not restricted:
                return (ObservedContent(content=content, source_node_ids=parent_ids),)
            node = graph.derive(
                parent_ids,
                Transformation.EXTRACT,
                allowed,
                destination_restricted=True,
            )
            return (ObservedContent(content=content, source_node_ids=(node.node_id,)),)
        observed: list[ObservedContent] = []
        for path, value in fields:
            field_content = f"{path}: {value}"
            _, allowed, restricted = self._canary_security(field_content, DataSensitivity.INTERNAL)
            node = graph.derive(
                parent_ids,
                Transformation.EXTRACT,
                allowed,
                destination_restricted=restricted,
            )
            observed.append(ObservedContent(content=field_content, source_node_ids=(node.node_id,)))
        return tuple(observed)

    def _observed(self, request: DefenseRequest) -> tuple[ObservedContent, ...]:
        _, _, _, _, graph, _, _ = self._require_bound()
        self._import_provenance(request)
        items = list(request.conversation)
        if request.observation is not None:
            items.append(
                ConversationItem(
                    role="tool",
                    kind=request.observation.kind,
                    content=request.observation.content,
                    provenance_ids=request.observation.provenance_ids,
                )
            )
        observed: list[ObservedContent] = []
        seen: set[tuple[str, tuple[str, ...]]] = set()
        for item in items:
            node_ids = tuple(
                self._source_ids[provenance_id]
                for provenance_id in item.provenance_ids
                if provenance_id in self._source_ids
            )
            if not node_ids:
                trust, default, conservative = self._fallback_source(item)
                node = graph.add_source(
                    item.kind or item.role,
                    trust,
                    default,
                    destination_restricted=conservative,
                )
                node_ids = (node.node_id,)
            for base in self._field_observations(item.content, node_ids):
                key = (base.content, base.source_node_ids)
                if key in seen:
                    continue
                seen.add(key)
                observed.extend(derive_observed_variants(graph, base))
        return tuple(observed)

    def _candidate_observed(self, action: CandidateAction) -> ObservedContent:
        _, _, _, _, graph, _, _ = self._require_bound()
        text = action.text_payload()
        sensitivity, allowed, restricted = self._canary_security(text, DataSensitivity.INTERNAL)
        node = graph.add_source(
            "candidate_payload",
            TrustLevel.ADVERSARY_CONTROLLED,
            sensitivity,
            allowed,
            destination_restricted=restricted,
        )
        return ObservedContent(content=text, source_node_ids=(node.node_id,))

    def _workflow(self) -> WorkflowState:
        assert self._state is not None
        resources: list[ResourceState] = []
        for collection in ("payments", "remediations", "incidents", "tickets"):
            for record_id, record in sorted(self._state.collections.get(collection, {}).items()):
                status = record.get("status")
                if isinstance(status, str) and status:
                    resources.append(ResourceState(resource=record_id, lifecycle=status))
        return WorkflowState(
            version=self._state_version,
            resources=tuple(resources),
            succeeded_tools=tuple(self._succeeded_tools),
        )

    def _evaluate(
        self,
        action: CandidateAction,
        observed: tuple[ObservedContent, ...],
        step_id: int,
        now: datetime,
    ) -> tuple[NormalizedAction, DecisionContext, GateEvaluation]:
        _, policy, scope, _, graph, adapters, evaluator = self._require_bound()
        complete_observed = (*observed, self._candidate_observed(action))
        normalized = adapters.normalize(action, complete_observed)
        context = DecisionContext(
            run_id=policy.run_id,
            session_id=graph.session_id,
            step_id=step_id,
            live_agent_state=self._workflow(),
            candidate=normalized,
            provenance=graph.nodes,
            active_policy_hash=policy.policy_hash,
            task_scope=scope,
            observed_content=complete_observed,
        )
        return normalized, context, evaluator.evaluate(context, now)

    # ---- rewrite service ------------------------------------------------------------------
    def _safe_rewrite(self, original: CandidateAction, evaluation: GateEvaluation) -> CandidateAction | None:
        reasons = set(evaluation.reason_codes)
        if original.tool == "email_send" and reasons & {
            "SENSITIVE_EGRESS",
            "DESTINATION_SENSITIVITY_DENIED",
        }:
            destination = original.arguments.get("to")
            if isinstance(destination, str):
                return CandidateAction(
                    type=ActionType.TOOL_CALL,
                    tool="email_draft",
                    arguments={
                        "to": destination,
                        "subject": "Restricted draft (content withheld)",
                        "body": "[REDACTED BY SENTINEL: sensitive content withheld]",
                    },
                )
        if original.tool == "incident_update" and "TASK_PARAMETER_DENIED" in reasons:
            incident_id = original.arguments.get("incident_id")
            if isinstance(incident_id, str):
                return CandidateAction(
                    type=ActionType.TOOL_CALL,
                    tool="incident_update",
                    arguments={
                        "incident_id": incident_id,
                        "status": "investigating",
                        "note": "SENTINEL withheld a privileged lifecycle change for review.",
                    },
                )
        return None

    # ---- trace emission -------------------------------------------------------------------
    def _link(self, normalized: NormalizedAction, state_version: int) -> dict[str, Any]:
        manifest, policy, scope, _, _, _, _ = self._require_bound()
        return {
            "action_digest": normalized.action_digest,
            "policy_version": policy.policy_version,
            "policy_hash": policy.policy_hash,
            "tool_spec_version": normalized.tool_spec_version or manifest.version,
            "normalizer_version": normalized.normalizer_version,
            "authorized_state_version": state_version,
            "task_id": scope.task_id,
        }

    def _append(self, event_type: EventType, actor: Actor, step_id: int, payload: dict[str, Any]) -> None:
        assert self._log is not None
        self._log.append(event_type, actor, step_id, payload)

    def _emit_decision(
        self,
        request: DefenseRequest,
        original: NormalizedAction,
        effective: NormalizedAction,
        evaluation: GateEvaluation,
        outcome: Decision,
        replacement: CandidateAction | None,
        rewrite_revalidation: GateEvaluation | None = None,
    ) -> None:
        link = self._link(effective, self._state_version)
        proposal_payload = {
            **link,
            "emitter": "decision_service",
            "original_action_digest": original.action_digest,
            "original_proposal": request.candidate_action.model_dump(mode="json"),
        }
        self._append(EventType.ACTION_PROPOSAL, Actor.DEFENSE, request.step_id, proposal_payload)
        self._traced_actions.add((effective.action_digest, self._state_version))
        if replacement is not None:
            self._append(
                EventType.ACTION_REWRITE,
                Actor.DEFENSE,
                request.step_id,
                {
                    **link,
                    "emitter": "decision_service",
                    "original_action_digest": original.action_digest,
                    "replacement": replacement.model_dump(mode="json"),
                },
            )
        self._append(
            EventType.FIREWALL_DECISION,
            Actor.DEFENSE,
            request.step_id,
            {
                **link,
                "emitter": "decision_service",
                "original_action_digest": original.action_digest,
                "outcome": outcome.value,
                "reason_codes": list(evaluation.reason_codes),
                "risk_score": evaluation.risk_score,
                "gates": [gate.model_dump(mode="json") for gate in evaluation.gate_results],
                "rewrite_revalidation_gates": [
                    gate.model_dump(mode="json") for gate in rewrite_revalidation.gate_results
                ]
                if rewrite_revalidation is not None
                else [],
                "provenance": {
                    "node_count": len(self._graph.nodes) if self._graph is not None else 0,
                    "dependency_count": len(effective.dependency_node_ids),
                },
                "replacement": replacement.model_dump(mode="json") if replacement else None,
            },
        )

    @staticmethod
    def _metadata(normalized: NormalizedAction, evaluation: GateEvaluation, policy: PolicySnapshot) -> dict[str, Any]:
        return {
            "action_digest": normalized.action_digest,
            "policy_version": policy.policy_version,
            "policy_hash": policy.policy_hash,
            "tool_spec_version": normalized.tool_spec_version,
            "normalizer_version": normalized.normalizer_version,
            "gates": [
                {
                    "gate": gate.gate.value,
                    "applicable": gate.applicable,
                    "passed": gate.passed,
                    "reason_codes": list(gate.reason_codes),
                }
                for gate in evaluation.gate_results
            ],
        }

    # ---- defense contract -----------------------------------------------------------------
    def decide(self, request: DefenseRequest) -> DefenseDecision:
        if not self._bound:
            return DefenseDecision(
                decision=Decision.BLOCK,
                risk_score=1.0,
                confidence=1.0,
                reason_codes=["SECURITY_CONTEXT_MISSING"],
                explanation="Trusted runtime policy and task scope are not bound.",
            )
        _, policy, _, _, graph, adapters, _ = self._require_bound()
        if request.run_id != policy.run_id:
            return DefenseDecision(
                decision=Decision.BLOCK,
                risk_score=1.0,
                confidence=1.0,
                reason_codes=["RUN_BINDING_MISMATCH"],
            )
        observed = self._observed(request)
        self._observed_by_step[request.step_id] = observed
        decision_time = request.runtime_timestamp or datetime.fromisoformat("2026-09-01T00:00:00+00:00")
        try:
            original, _, evaluation = self._evaluate(
                request.candidate_action,
                observed,
                request.step_id,
                decision_time,
            )
        except ActionNormalizationError as exc:
            raw = request.candidate_action
            normalized = NormalizedAction(
                raw_proposal=raw,
                executable=raw,
                tool_spec_version=None,
                normalizer_version=adapters.manifest.normalizer_version,
                action_digest=raw.digest(),
            )
            self._decision_actions.setdefault(request.step_id, set()).add(normalized.action_digest)
            # Unknown/malformed proposals are recorded but never reach the executor.
            self._append(
                EventType.ACTION_PROPOSAL,
                Actor.DEFENSE,
                request.step_id,
                {
                    **self._link(normalized, self._state_version),
                    "emitter": "decision_service",
                    "original_action_digest": normalized.action_digest,
                    "original_proposal": raw.model_dump(mode="json"),
                },
            )
            self._traced_actions.add((normalized.action_digest, self._state_version))
            self._append(
                EventType.FIREWALL_DECISION,
                Actor.DEFENSE,
                request.step_id,
                {
                    **self._link(normalized, self._state_version),
                    "emitter": "decision_service",
                    "original_action_digest": normalized.action_digest,
                    "outcome": Decision.BLOCK.value,
                    "reason_codes": [exc.reason_code],
                    "risk_score": 1.0,
                    "gates": [],
                    "provenance": {"node_count": len(graph.nodes), "dependency_count": 0},
                    "replacement": None,
                },
            )
            return DefenseDecision(
                decision=Decision.BLOCK,
                risk_score=1.0,
                confidence=1.0,
                reason_codes=[exc.reason_code],
                explanation="Strict action normalization failed.",
            )

        effective = original
        effective_evaluation = evaluation
        outcome = evaluation.outcome
        replacement: CandidateAction | None = None
        if outcome is Decision.BLOCK:
            candidate = self._safe_rewrite(request.candidate_action, evaluation)
            if candidate is not None:
                rewritten, _, rewritten_evaluation = self._evaluate(candidate, observed, request.step_id, decision_time)
                if rewritten_evaluation.outcome is Decision.ALLOW:
                    effective = rewritten
                    effective_evaluation = rewritten_evaluation
                    outcome = Decision.REWRITE
                    replacement = rewritten.executable
                elif rewritten_evaluation.outcome is Decision.ESCALATE:
                    effective = rewritten
                    effective_evaluation = rewritten_evaluation
                    outcome = Decision.ESCALATE
        self._decision_actions.setdefault(request.step_id, set()).add(effective.action_digest)
        decision_evaluation = evaluation if outcome is Decision.REWRITE else effective_evaluation
        self._emit_decision(
            request,
            original,
            effective,
            decision_evaluation,
            outcome,
            replacement,
            effective_evaluation if outcome is Decision.REWRITE else None,
        )
        reason_codes = (
            ["POLICY_SAFE_REWRITE", *evaluation.reason_codes]
            if outcome is Decision.REWRITE
            else list(effective_evaluation.reason_codes)
        )
        return DefenseDecision(
            decision=outcome,
            risk_score=decision_evaluation.risk_score,
            confidence=decision_evaluation.confidence,
            reason_codes=list(dict.fromkeys(reason_codes)),
            explanation="Deterministic G1-G7 policy decision.",
            rewritten_action=replacement,
            metadata=self._metadata(effective, effective_evaluation, policy),
        )

    # ---- approval and guarded execution ---------------------------------------------------
    def record_human_approval(
        self,
        target: CandidateAction,
        *,
        approved: bool,
        step_id: int,
        timestamp: datetime,
    ) -> None:
        manifest, policy, scope, _, _, adapters, _ = self._require_bound()
        observed = self._observed_by_step.get(step_id, ())
        try:
            normalized = adapters.normalize(target, (*observed, self._candidate_observed(target)))
        except ActionNormalizationError:
            return
        issuer_role = scope.approval_roles[0] if scope.approval_roles else "unauthorized"
        record = self._approvals.issue(
            issuer_id="simulated-human",
            issuer_role=issuer_role,
            task_id=scope.task_id,
            action_digest=normalized.action_digest,
            policy_version=policy.policy_version,
            policy_hash=policy.policy_hash,
            state_version=self._state_version,
            expires_at=timestamp + APPROVAL_TTL,
            decision=ApprovalDecision.APPROVED if approved else ApprovalDecision.DENIED,
        )
        spec = manifest.get(normalized.executable.tool or "")
        amounts = {
            field: normalized.executable.arguments[field]
            for field in (spec.amount_fields if spec else ())
            if field in normalized.executable.arguments
        }
        trace_key = (normalized.action_digest, self._state_version)
        if trace_key not in self._traced_actions:
            self._append(
                EventType.ACTION_PROPOSAL,
                Actor.DEFENSE,
                step_id,
                {
                    **self._link(normalized, self._state_version),
                    "emitter": "decision_service",
                    "original_action_digest": normalized.action_digest,
                    "original_proposal": target.model_dump(mode="json"),
                    "source": "confirmation_target",
                },
            )
            self._traced_actions.add(trace_key)
        self._append(
            EventType.APPROVAL_RECORD,
            Actor.DEFENSE,
            step_id,
            {
                **self._link(normalized, self._state_version),
                "emitter": "decision_service",
                "record_id": record.record_id,
                "decision": record.decision.value,
                "issuer_role": record.issuer_role,
                "expires_at": record.expires_at.isoformat(),
                "tool": normalized.executable.tool,
                "approval_view": {
                    "effect": spec.effect_class.value if spec else "unknown",
                    "destinations": list(normalized.canonical_destinations),
                    "amounts": amounts,
                    "policy_condition": spec.approval_rule.value if spec else "unknown",
                    "provenance_dependencies": len(normalized.dependency_node_ids),
                },
            },
        )

    def prepare_execution(self, action: CandidateAction, *, step_id: int, timestamp: datetime) -> GuardedPreparation:
        _, policy, _, _, _, _, _ = self._require_bound()
        observed = self._observed_by_step.get(step_id, ())
        try:
            normalized, context, evaluation = self._evaluate(action, observed, step_id, timestamp)
        except ActionNormalizationError as exc:
            return GuardedPreparation(action, action.digest(), self._state_version, None, exc.reason_code)
        if normalized.action_digest not in self._decision_actions.get(step_id, set()):
            return GuardedPreparation(
                normalized.executable,
                normalized.action_digest,
                context.live_agent_state.version,
                None,
                "NO_MATCHING_DECISION",
            )
        if evaluation.outcome is not Decision.ALLOW:
            return GuardedPreparation(
                normalized.executable,
                normalized.action_digest,
                context.live_agent_state.version,
                None,
                ",".join(evaluation.reason_codes),
            )
        material = f"{policy.run_id}:{step_id}:{normalized.action_digest}:{self._permit_counter}".encode()
        self._permit_counter += 1
        permit_id = "permit_" + hashlib.sha256(material).hexdigest()[:24]
        permit = _Permit(permit_id, step_id, normalized.action_digest, context.live_agent_state.version)
        self._permits[permit_id] = permit
        return GuardedPreparation(
            normalized.executable,
            normalized.action_digest,
            context.live_agent_state.version,
            permit_id,
        )

    @staticmethod
    def _approval_required(
        rule: ApprovalRule,
        arguments: dict[str, Any],
        field: str | None,
        values: tuple[str, ...],
    ) -> bool:
        if rule is ApprovalRule.ALWAYS:
            return True
        return rule is ApprovalRule.CONDITIONAL and field is not None and str(arguments.get(field)) in values

    def _state_digest(self) -> str:
        assert self._state is not None
        encoded = json.dumps(self._state.snapshot(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def _emit_execution(
        self,
        preparation: GuardedPreparation,
        outcome: ToolOutcome,
        *,
        step_id: int,
        old_state_version: int,
    ) -> None:
        manifest, policy, scope, _, _, _, _ = self._require_bound()
        spec = manifest.get(preparation.action.tool or "")
        link = {
            "action_digest": preparation.action_digest,
            "policy_version": policy.policy_version,
            "policy_hash": policy.policy_hash,
            "tool_spec_version": spec.version if spec else manifest.version,
            "normalizer_version": manifest.normalizer_version,
            "authorized_state_version": old_state_version,
            "task_id": scope.task_id,
        }
        self._append(
            EventType.EXECUTOR_RECEIPT,
            Actor.TOOL_GATEWAY,
            step_id,
            {
                **link,
                "emitter": "guarded_executor",
                "tool": preparation.action.tool,
                "executed_action": preparation.action.model_dump(mode="json"),
                "succeeded": outcome.succeeded,
                "error": outcome.error,
                "effects": [name for name, _ in outcome.effects],
            },
        )
        self._append(
            EventType.STATE_VERIFIED,
            Actor.TOOL_GATEWAY,
            step_id,
            {
                **link,
                "emitter": "guarded_executor",
                "new_state_version": self._state_version,
                "state_digest": self._state_digest(),
                "effect_count": len(self._state.effects) if self._state is not None else 0,
            },
        )

    def execute_prepared(
        self,
        preparation: GuardedPreparation,
        *,
        step_id: int,
        timestamp: datetime,
    ) -> GatewayResult:
        manifest, policy, scope, _, _, _, _ = self._require_bound()
        assert self._registry is not None
        assert self._gateway is not None
        tool = self._registry.get(preparation.action.tool or "")
        old_version = self._state_version
        if not preparation.permitted:
            outcome = ToolOutcome.failure(f"guarded execution denied: {preparation.error or 'invalid permit'}")
            self._emit_execution(preparation, outcome, step_id=step_id, old_state_version=old_version)
            return GatewayResult(tool, outcome, None)
        permit = self._permits.pop(preparation.permit_id or "", None)
        if (
            permit is None
            or permit.step_id != step_id
            or permit.action_digest != preparation.action_digest
            or permit.state_version != self._state_version
        ):
            outcome = ToolOutcome.failure("guarded execution denied: stale or replayed permit")
            self._emit_execution(preparation, outcome, step_id=step_id, old_state_version=old_version)
            return GatewayResult(tool, outcome, None)
        observed = self._observed_by_step.get(step_id, ())
        normalized, _, evaluation = self._evaluate(preparation.action, observed, step_id, timestamp)
        if normalized.action_digest != preparation.action_digest or evaluation.outcome is not Decision.ALLOW:
            outcome = ToolOutcome.failure("guarded execution denied: revalidation failed")
            self._emit_execution(preparation, outcome, step_id=step_id, old_state_version=old_version)
            return GatewayResult(tool, outcome, None)
        spec = manifest.get(preparation.action.tool or "")
        if spec is None:
            outcome = ToolOutcome.failure("guarded execution denied: missing ToolSpec")
            self._emit_execution(preparation, outcome, step_id=step_id, old_state_version=old_version)
            return GatewayResult(tool, outcome, None)
        if self._approval_required(
            spec.approval_rule,
            preparation.action.arguments,
            spec.approval_field,
            spec.approval_values,
        ):
            status = self._approvals.consume(
                task_id=scope.task_id,
                action_digest=normalized.action_digest,
                policy_version=policy.policy_version,
                policy_hash=policy.policy_hash,
                state_version=self._state_version,
                allowed_roles=scope.approval_roles,
                now=timestamp,
            )
            if status is not ApprovalStatus.VALID:
                outcome = ToolOutcome.failure(f"guarded execution denied: approval {status.value}")
                self._emit_execution(preparation, outcome, step_id=step_id, old_state_version=old_version)
                return GatewayResult(tool, outcome, None)
        result = self._gateway.execute(preparation.action, step_id, timestamp)
        if result.outcome.succeeded:
            self._succeeded_tools.append(spec.name)
            if spec.effect_class is not EffectClass.READ:
                self._state_version += 1
        self._emit_execution(preparation, result.outcome, step_id=step_id, old_state_version=old_version)
        return result
