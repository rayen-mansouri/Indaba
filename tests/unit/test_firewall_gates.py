from datetime import UTC, datetime, timedelta

import pytest

from sentinel.core.actions import ActionType, CandidateAction, Decision
from sentinel.core.policies import load_policy
from sentinel.core.provenance import TrustLevel
from sentinel.firewall.approvals import ApprovalDecision, ApprovalStatus, ApprovalStore
from sentinel.firewall.gates import GateEvaluator, GateName
from sentinel.firewall.normalization import DestinationMap, TrustedActionAdapters
from sentinel.firewall.policy import PolicySnapshot
from sentinel.firewall.provenance import ProvenanceGraph
from sentinel.firewall.records import (
    AuthenticatedPrincipal,
    CapabilityGrant,
    DataSensitivity,
    DecisionContext,
    NormalizedAction,
    ObservedContent,
    ResourceState,
    TaskScope,
    WorkflowState,
)
from sentinel.firewall.toolspecs import build_official_tool_manifest
from sentinel.tools.registry import registry_for_domain
from tests.conftest import ROOT

NOW = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)


def _tools():  # type: ignore[no-untyped-def]
    return tuple(tool for domain in ("enterprise", "finance", "soc") for tool in registry_for_domain(domain))


def _principal(authenticated_by: str = "simulator_identity") -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        principal_id="operator-1",
        role="operator",
        authenticated_by=authenticated_by,
    )


def _runtime(
    policy_name: str,
    allowed_tools: tuple[str, ...],
    destinations: DestinationMap | None = None,
):  # type: ignore[no-untyped-def]
    manifest = build_official_tool_manifest()
    policy = PolicySnapshot.capture("run-1", load_policy(ROOT, policy_name), manifest, allowed_tools)
    destination_map = destinations or DestinationMap(internal_email_domains=("atlas.example",))
    approvals = ApprovalStore()
    adapters = TrustedActionAdapters(_tools(), manifest, destination_map)
    evaluator = GateEvaluator(manifest, policy, approvals, destination_map)
    return policy, approvals, adapters, evaluator


def _context(
    *,
    policy: PolicySnapshot,
    adapters: TrustedActionAdapters,
    action: CandidateAction,
    grants: tuple[CapabilityGrant, ...],
    workflow: WorkflowState,
    sensitivity: DataSensitivity = DataSensitivity.INTERNAL,
    trust: TrustLevel = TrustLevel.AUTHENTICATED_USER,
    approval_roles: tuple[str, ...] = ("officer",),
    authenticated_by: str = "simulator_identity",
) -> DecisionContext:
    graph = ProvenanceGraph("run-1", "session-1")
    node = graph.add_source("user", trust, sensitivity)
    text = " ".join(str(value) for value in action.arguments.values())
    observed = (ObservedContent(content=text, source_node_ids=(node.node_id,)),)
    candidate = adapters.normalize(action, observed)
    return DecisionContext(
        run_id="run-1",
        session_id="session-1",
        step_id=1,
        live_agent_state=workflow,
        candidate=candidate,
        provenance=graph.nodes,
        active_policy_hash=policy.policy_hash,
        task_scope=TaskScope(
            task_id="task-1",
            principal=_principal(authenticated_by),
            grants=grants,
            approval_roles=approval_roles,
            issued_state_version=0,
        ),
        observed_content=observed,
    )


def _payment_prepare() -> CandidateAction:
    return CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="payment_prepare",
        arguments={
            "account_id": "ACC-1001",
            "beneficiary_id": "BEN-01",
            "amount": 1250,
            "reference": "CASE-7001 refund",
        },
    )


def _prepare_grant(max_amount: float = 1250) -> CapabilityGrant:
    return CapabilityGrant(
        tool="payment_prepare",
        capabilities=("write",),
        resources=("ACC-1001", "BEN-01"),
        destinations=("BEN-01",),
        max_amount=max_amount,
        currency="TND",
    )


def test_all_seven_gates_are_reported_and_scoped_prepare_is_allowed() -> None:
    policy, _, adapters, evaluator = _runtime("finance_standard", ("payment_prepare",))
    context = _context(
        policy=policy,
        adapters=adapters,
        action=_payment_prepare(),
        grants=(_prepare_grant(),),
        workflow=WorkflowState(version=0),
    )
    result = evaluator.evaluate(context, NOW)
    assert result.outcome is Decision.ALLOW
    assert result.risk_score == 0.03 and result.confidence == 0.99
    assert {gate.gate for gate in result.gate_results} == set(GateName)


def test_g1_and_g2_reject_effect_without_task_authority() -> None:
    policy, _, adapters, evaluator = _runtime("finance_standard", ("payment_prepare",))
    context = _context(
        policy=policy,
        adapters=adapters,
        action=_payment_prepare(),
        grants=(),
        workflow=WorkflowState(version=0),
        trust=TrustLevel.UNTRUSTED_EXTERNAL,
    )
    result = evaluator.evaluate(context, NOW)
    assert result.outcome is Decision.BLOCK
    assert "NO_TRUSTED_EFFECT_AUTHORITY" in result.reason_codes
    assert "TASK_CAPABILITY_DENIED" in result.reason_codes


def test_g2_enforces_amount_and_resource_constraints() -> None:
    policy, _, adapters, evaluator = _runtime("finance_standard", ("payment_prepare",))
    grant = _prepare_grant(max_amount=1000).model_copy(update={"resources": ("ACC-OTHER", "BEN-01")})
    context = _context(
        policy=policy,
        adapters=adapters,
        action=_payment_prepare(),
        grants=(grant,),
        workflow=WorkflowState(version=0),
    )
    result = evaluator.evaluate(context, NOW)
    assert result.outcome is Decision.BLOCK
    assert "TASK_AMOUNT_DENIED" in result.reason_codes
    assert "TASK_RESOURCE_DENIED" in result.reason_codes


def test_g3_and_g4_require_authoritative_lifecycle_and_bound_approval() -> None:
    allowed = ("payment_confirm",)
    policy, approvals, adapters, evaluator = _runtime("finance_standard", allowed)
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="payment_confirm",
        arguments={"payment_id": "PAY-0001"},
    )
    grant = CapabilityGrant(
        tool="payment_confirm",
        capabilities=("state_change",),
        resources=("PAY-0001",),
    )
    wrong_state = _context(
        policy=policy,
        adapters=adapters,
        action=action,
        grants=(grant,),
        workflow=WorkflowState(
            version=3,
            resources=(ResourceState(resource="PAY-0001", lifecycle="executed"),),
            succeeded_tools=("payment_prepare",),
        ),
    )
    assert "LIFECYCLE_MISMATCH" in evaluator.evaluate(wrong_state, NOW).reason_codes

    context = _context(
        policy=policy,
        adapters=adapters,
        action=action,
        grants=(grant,),
        workflow=WorkflowState(
            version=3,
            resources=(ResourceState(resource="PAY-0001", lifecycle="prepared"),),
            succeeded_tools=("payment_prepare",),
        ),
    )
    missing = evaluator.evaluate(context, NOW)
    assert missing.outcome is Decision.ESCALATE
    assert missing.risk_score == 0.55 and missing.confidence == 0.97
    approvals.issue(
        issuer_id="officer-1",
        issuer_role="officer",
        task_id="task-1",
        action_digest=context.candidate.action_digest,
        policy_version=policy.policy_version,
        policy_hash=policy.policy_hash,
        state_version=3,
        expires_at=NOW + timedelta(minutes=5),
        decision=ApprovalDecision.APPROVED,
    )
    assert evaluator.evaluate(context, NOW).outcome is Decision.ALLOW


def test_g5_rejects_memory_as_authority() -> None:
    policy, _, adapters, evaluator = _runtime("finance_standard", ("payment_prepare",))
    context = _context(
        policy=policy,
        adapters=adapters,
        action=_payment_prepare(),
        grants=(_prepare_grant(),),
        workflow=WorkflowState(version=0),
        authenticated_by="memory",
    )
    assert "UNPROTECTED_AUTHORITY_SOURCE" in evaluator.evaluate(context, NOW).reason_codes


def test_g6_blocks_confidential_external_egress_even_when_destination_is_authorized() -> None:
    policy, _, adapters, evaluator = _runtime("enterprise_standard", ("email_send",))
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_send",
        arguments={"to": "vendor@outside.example", "subject": "Status", "body": "Restricted status"},
    )
    grant = CapabilityGrant(
        tool="email_send",
        capabilities=("message",),
        destinations=("vendor@outside.example",),
    )
    context = _context(
        policy=policy,
        adapters=adapters,
        action=action,
        grants=(grant,),
        workflow=WorkflowState(version=0),
        sensitivity=DataSensitivity.CONFIDENTIAL,
    )
    result = evaluator.evaluate(context, NOW)
    assert result.outcome is Decision.BLOCK
    assert "SENSITIVE_EGRESS" in result.reason_codes


def test_g6_fails_safe_when_payload_sensitivity_is_unknown() -> None:
    policy, _, adapters, evaluator = _runtime("finance_standard", ("case_note_create",))
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="case_note_create",
        arguments={"case_id": "CASE-7001", "text": "unattributed note"},
    )
    grant = CapabilityGrant(
        tool="case_note_create",
        capabilities=("write",),
        resources=("CASE-7001",),
        destinations=("CASE-7001",),
    )
    context = _context(
        policy=policy,
        adapters=adapters,
        action=action,
        grants=(grant,),
        workflow=WorkflowState(version=0),
        sensitivity=DataSensitivity.UNKNOWN,
    )
    assert "UNKNOWN_SENSITIVITY" in evaluator.evaluate(context, NOW).reason_codes


def test_g7_rejects_destination_substitution() -> None:
    policy, _, adapters, evaluator = _runtime("enterprise_standard", ("email_send",))
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_send",
        arguments={"to": "evil@outside.example", "subject": "Public", "body": "Public update"},
    )
    grant = CapabilityGrant(
        tool="email_send",
        capabilities=("message",),
        destinations=("security@atlas.example",),
    )
    context = _context(
        policy=policy,
        adapters=adapters,
        action=action,
        grants=(grant,),
        workflow=WorkflowState(version=0),
        sensitivity=DataSensitivity.PUBLIC,
    )
    assert "DESTINATION_NOT_AUTHORIZED" in evaluator.evaluate(context, NOW).reason_codes


def test_unknown_tools_and_malformed_policy_binding_fail_closed() -> None:
    policy, _, adapters, evaluator = _runtime("finance_standard", ("payment_prepare",))
    context = _context(
        policy=policy,
        adapters=adapters,
        action=_payment_prepare(),
        grants=(_prepare_grant(),),
        workflow=WorkflowState(version=0),
    )
    unknown = CandidateAction(type=ActionType.TOOL_CALL, tool="made_up_tool", arguments={})
    unknown_candidate = NormalizedAction(
        raw_proposal=unknown,
        executable=unknown,
        tool_spec_version="1.0.0",
        normalizer_version="sentinel-c14n/1",
        action_digest=unknown.digest(),
    )
    unknown_context = context.model_copy(update={"candidate": unknown_candidate})
    assert "UNKNOWN_TOOL" in evaluator.evaluate(unknown_context, NOW).reason_codes
    bad_policy_context = context.model_copy(update={"active_policy_hash": "b" * 64})
    assert "MALFORMED_SECURITY_METADATA" in evaluator.evaluate(bad_policy_context, NOW).reason_codes


def test_optional_absent_payload_is_not_treated_as_unknown_egress() -> None:
    policy, _, adapters, evaluator = _runtime("soc_standard", ("incident_update",))
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="incident_update",
        arguments={"incident_id": "INC-0001", "status": "investigating"},
    )
    grant = CapabilityGrant(
        tool="incident_update",
        capabilities=("state_change", "write"),
        resources=("INC-0001",),
        destinations=("INC-0001",),
    )
    context = _context(
        policy=policy,
        adapters=adapters,
        action=action,
        grants=(grant,),
        workflow=WorkflowState(
            version=0,
            resources=(ResourceState(resource="INC-0001", lifecycle="investigating"),),
        ),
        sensitivity=DataSensitivity.UNKNOWN,
    )
    result = evaluator.evaluate(context, NOW)
    assert result.outcome is Decision.ALLOW
    g6 = next(item for item in result.gate_results if item.gate is GateName.G6_CONFIDENTIALITY)
    assert not g6.applicable


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"expires_at": NOW}, ApprovalStatus.EXPIRED),
        ({"state_version": 2}, ApprovalStatus.STALE_STATE),
        ({"policy_hash": "b" * 64}, ApprovalStatus.STALE_POLICY),
        ({"issuer_role": "requester"}, ApprovalStatus.INVALID_ROLE),
        ({"decision": ApprovalDecision.DENIED}, ApprovalStatus.DENIED),
    ],
)
def test_approval_store_rejects_expiry_staleness_role_and_denial(change, expected) -> None:  # type: ignore[no-untyped-def]
    store = ApprovalStore()
    values = {
        "issuer_id": "officer-1",
        "issuer_role": "officer",
        "task_id": "task-1",
        "action_digest": "digest-1",
        "policy_version": 1,
        "policy_hash": "a" * 64,
        "state_version": 1,
        "expires_at": NOW + timedelta(minutes=5),
        "decision": ApprovalDecision.APPROVED,
    }
    store.issue(**(values | change))
    status = store.status(
        task_id="task-1",
        action_digest="digest-1",
        policy_version=1,
        policy_hash="a" * 64,
        state_version=1,
        allowed_roles=("officer",),
        now=NOW,
    )
    assert status is expected


def test_approval_is_consumed_once_and_replay_is_rejected() -> None:
    store = ApprovalStore()
    store.issue(
        issuer_id="officer-1",
        issuer_role="officer",
        task_id="task-1",
        action_digest="digest-1",
        policy_version=1,
        policy_hash="a" * 64,
        state_version=1,
        expires_at=NOW + timedelta(minutes=5),
        decision=ApprovalDecision.APPROVED,
    )
    values = {
        "task_id": "task-1",
        "action_digest": "digest-1",
        "policy_version": 1,
        "policy_hash": "a" * 64,
        "state_version": 1,
        "allowed_roles": ("officer",),
        "now": NOW,
    }
    assert store.consume(**values) is ApprovalStatus.VALID
    assert store.consume(**values) is ApprovalStatus.REPLAYED
