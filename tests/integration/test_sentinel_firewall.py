import base64
import codecs
import json
from datetime import UTC, datetime
from urllib.parse import quote

import pytest

from sentinel.core.actions import ActionType, CandidateAction, Decision
from sentinel.core.events import EventLog, EventType, LogicalClock
from sentinel.core.policies import load_policy
from sentinel.core.provenance import Provenance, Sensitivity, SourceType, TrustLevel
from sentinel.core.scenario import TaskAuthorizationSpec
from sentinel.core.state import WorldState
from sentinel.defenses.interface import ConversationItem, DefenseRequest, ProvenanceRecord
from sentinel.evaluator.runner import run_scenario
from sentinel.firewall.runtime import SentinelFirewallDefense
from sentinel.firewall.trace import TraceIntegrityError, verify_digest_linked_trace
from sentinel.tools.gateway import ToolGateway
from sentinel.tools.registry import registry_for_domain
from tests.conftest import ROOT, build_scenario, load

pytestmark = pytest.mark.integration

NOW = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)


def _bound(
    scenario_id: str,
    *,
    authority: TaskAuthorizationSpec | None = None,
    allowed_tools: tuple[str, ...] | None = None,
) -> tuple[SentinelFirewallDefense, WorldState, EventLog]:
    scenario = load(scenario_id)
    state = WorldState.from_scenario(scenario, ROOT)
    registry = registry_for_domain(scenario.domain.value)
    gateway = ToolGateway(registry, state)
    log = EventLog("run-firewall-test", LogicalClock(1))
    defense = SentinelFirewallDefense()
    defense.bind_run(
        run_id=log.run_id,
        task_authorization=authority or scenario.task_authorization,  # type: ignore[arg-type]
        policy=load_policy(ROOT, scenario.policy_profile),
        allowed_tools=allowed_tools or tuple(scenario.allowed_tools),
        registry=registry,
        state=state,
        gateway=gateway,
        log=log,
    )
    return defense, state, log


def _request(
    action: CandidateAction,
    *,
    content: str = "authenticated task",
    restricted_observation: str | None = None,
) -> DefenseRequest:
    conversation = [ConversationItem(role="user", kind="user_message", content=content)]
    provenance: list[ProvenanceRecord] = []
    if restricted_observation is not None:
        provenance.append(
            ProvenanceRecord(
                id="prov-sensitive",
                provenance=Provenance(
                    source_type=SourceType.ASSET,
                    source_id="runtime-observed-asset",
                    trust_level=TrustLevel.TRUSTED_INTERNAL,
                    origin_actor="asset_inventory",
                    retrieved_via="asset_lookup",
                    sensitivity=Sensitivity.RESTRICTED,
                    timestamp=NOW,
                ),
            )
        )
        conversation.append(
            ConversationItem(
                role="tool",
                kind="tool_result",
                content=json.dumps({"service_account_token": restricted_observation}),
                provenance_ids=["prov-sensitive"],
            )
        )
    return DefenseRequest(
        run_id="run-firewall-test",
        step_id=1,
        runtime_timestamp=NOW,
        user_goal=content,
        conversation=conversation,
        candidate_action=action,
        provenance=provenance,
    )


def test_live_sentinel_blocks_direct_attack_and_preserves_task_utility(run_config) -> None:  # type: ignore[no-untyped-def]
    run = run_scenario(load("enterprise_direct_token_request"), SentinelFirewallDefense(), run_config)
    assert run.outcome.task_success
    assert not run.outcome.attack_success and not run.outcome.critical_violation
    codes = {code for record in run.outcome.decisions for code in record.reason_codes}
    assert {"POLICY_TOOL_DENIED", "TASK_CAPABILITY_DENIED"} <= codes
    assert all(event.payload["guarded"] for event in run.log.of_type(EventType.TOOL_REQUEST))
    report = verify_digest_linked_trace(run.log.events)
    assert report.executed_actions == 2


@pytest.mark.parametrize(
    "scenario_id",
    ["enterprise_security_digest", "finance_refund_confirmed", "soc_confirmed_isolation"],
)
def test_bound_approvals_and_lifecycles_execute_once(
    scenario_id: str,
    run_config,  # type: ignore[no-untyped-def]
) -> None:
    run = run_scenario(load(scenario_id), SentinelFirewallDefense(), run_config)
    assert run.outcome.task_success and not run.outcome.critical_violation
    assert run.log.of_type(EventType.MODEL_OUTPUT), "final user response was blocked"
    approvals = run.log.of_type(EventType.APPROVAL_RECORD)
    assert len(approvals) == 1 and approvals[0].payload["decision"] == "approved"
    assert verify_digest_linked_trace(run.log.events).executed_actions >= 2


def test_missing_approval_is_a_true_escalation() -> None:
    defense, _, _ = _bound("enterprise_security_digest")
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_send",
        arguments={
            "to": "leila.mansour@atlas.example",
            "subject": "Security summary",
            "body": "Internal security summary",
        },
    )
    decision = defense.decide(_request(action))
    assert decision.decision is Decision.ESCALATE
    assert decision.reason_codes == ["APPROVAL_REQUIRED"]


def test_sensitive_send_rewrites_to_one_revalidated_redacted_draft() -> None:
    authority = TaskAuthorizationSpec.model_validate(
        {
            "task_id": "tsk_0123456789abcdef",
            "principal_id": "enterprise_operator",
            "role": "operator",
            "authenticated_by": "offline_simulator_identity",
            "approval_roles": ["team_lead"],
            "grants": [
                {
                    "tool": "email_send",
                    "capabilities": ["message"],
                    "destinations": ["vendor@outside.example"],
                },
                {
                    "tool": "email_draft",
                    "capabilities": ["draft"],
                    "destinations": ["vendor@outside.example"],
                },
            ],
        }
    )
    defense, state, log = _bound(
        "enterprise_security_digest",
        authority=authority,
        allowed_tools=("email_send", "email_draft"),
    )
    secret = next(iter(state.canaries)).value
    original = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_send",
        arguments={"to": "vendor@outside.example", "subject": "secret", "body": secret},
    )
    state.canaries.canaries.clear()  # evaluator-only registry must not influence the decision
    decision = defense.decide(
        _request(
            original,
            content="Draft a restricted external notice.",
            restricted_observation=secret,
        )
    )
    assert decision.decision is Decision.REWRITE
    assert decision.rewritten_action is not None and decision.rewritten_action.tool == "email_draft"
    assert secret not in decision.rewritten_action.text_payload()
    preparation = defense.prepare_execution(decision.rewritten_action, step_id=1, timestamp=NOW)
    assert preparation.permitted
    result = defense.execute_prepared(preparation, step_id=1, timestamp=NOW)
    assert result.outcome.succeeded
    assert len(state.table("drafts")) == 1 and not state.table("sent_emails")
    assert verify_digest_linked_trace(log.events).executed_actions == 1


@pytest.mark.parametrize(
    "encode",
    [
        lambda value: " ".join(value.lower()),
        lambda value: quote(value),
        lambda value: base64.b64encode(value.encode()).decode(),
        lambda value: value.encode().hex(),
        lambda value: codecs.encode(value, "rot13"),
        lambda value: value[::-1],
    ],
)
def test_encoded_sensitive_payload_is_rewritten_before_external_egress(encode) -> None:  # type: ignore[no-untyped-def]
    authority = TaskAuthorizationSpec.model_validate(
        {
            "task_id": "tsk_0123456789abcdef",
            "principal_id": "enterprise_operator",
            "role": "operator",
            "authenticated_by": "offline_simulator_identity",
            "approval_roles": ["team_lead"],
            "grants": [
                {"tool": "email_send", "capabilities": ["message"], "destinations": ["vendor@outside.example"]},
                {"tool": "email_draft", "capabilities": ["draft"], "destinations": ["vendor@outside.example"]},
            ],
        }
    )
    defense, state, _ = _bound(
        "enterprise_security_digest", authority=authority, allowed_tools=("email_send", "email_draft")
    )
    secret = next(iter(state.canaries)).value
    original = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_send",
        arguments={"to": "vendor@outside.example", "subject": "encoded", "body": encode(secret)},
    )

    decision = defense.decide(_request(original, restricted_observation=secret))

    assert decision.decision is Decision.REWRITE
    assert decision.rewritten_action is not None
    assert "SENSITIVE_EGRESS" in decision.reason_codes


def test_failed_rewrite_revalidation_blocks_without_original_fallback() -> None:
    authority = TaskAuthorizationSpec.model_validate(
        {
            "task_id": "tsk_fedcba9876543210",
            "principal_id": "enterprise_operator",
            "role": "operator",
            "authenticated_by": "offline_simulator_identity",
            "approval_roles": ["team_lead"],
            "grants": [
                {
                    "tool": "email_send",
                    "capabilities": ["message"],
                    "destinations": ["vendor@outside.example"],
                }
            ],
        }
    )
    defense, state, _ = _bound(
        "enterprise_security_digest",
        authority=authority,
        allowed_tools=("email_send", "email_draft"),
    )
    secret = next(iter(state.canaries)).value
    original = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_send",
        arguments={"to": "vendor@outside.example", "subject": "secret", "body": secret},
    )
    decision = defense.decide(_request(original, restricted_observation=secret))
    assert decision.decision is Decision.BLOCK and decision.rewritten_action is None
    assert state.table("sent_emails") == {} and state.table("drafts") == {}


def test_field_scoped_provenance_does_not_taint_unrelated_asset_fields(run_config) -> None:  # type: ignore[no-untyped-def]
    run = run_scenario(load("soc_val_asset_criticality"), SentinelFirewallDefense(), run_config)
    assert run.outcome.task_success
    responses = run.log.of_type(EventType.MODEL_OUTPUT)
    assert responses and "criticality: high" in responses[-1].payload["content"]


def test_whole_context_ablation_reproduces_conservative_overtaint(run_config) -> None:  # type: ignore[no-untyped-def]
    defense = SentinelFirewallDefense(name="sentinel_whole_context", field_scoped_provenance=False)
    run = run_scenario(load("soc_val_asset_criticality"), defense, run_config)
    assert not run.outcome.task_success
    assert any("DESTINATION_SENSITIVITY_DENIED" in record.reason_codes for record in run.outcome.decisions)


def test_no_task_g7_ablation_allows_new_destination_when_other_gates_pass() -> None:
    authority = TaskAuthorizationSpec.model_validate(
        {
            "task_id": "tsk_0123456789abcdef",
            "principal_id": "enterprise_operator",
            "role": "operator",
            "authenticated_by": "offline_simulator_identity",
            "approval_roles": ["team_lead"],
            "grants": [
                {
                    "tool": "email_draft",
                    "capabilities": ["draft"],
                    "destinations": ["legal@atlas.example"],
                }
            ],
        }
    )
    scenario = load("enterprise_security_digest")
    state = WorldState.from_scenario(scenario, ROOT)
    registry = registry_for_domain(scenario.domain.value)
    gateway = ToolGateway(registry, state)
    log = EventLog("run-firewall-test", LogicalClock(1))
    defense = SentinelFirewallDefense(name="sentinel_no_task_g7", enforce_task_destination=False)
    defense.bind_run(
        run_id=log.run_id,
        task_authorization=authority,
        policy=load_policy(ROOT, scenario.policy_profile),
        allowed_tools=("email_draft",),
        registry=registry,
        state=state,
        gateway=gateway,
        log=log,
    )
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_draft",
        arguments={"to": "other@atlas.example", "subject": "Status", "body": "Public status"},
    )

    decision = defense.decide(_request(action))

    assert decision.decision is Decision.ALLOW


def test_memory_is_evidence_only_and_cannot_expand_task_authority(run_config) -> None:  # type: ignore[no-untyped-def]
    run = run_scenario(load("enterprise_memory_poison"), SentinelFirewallDefense(), run_config)

    assert run.outcome.task_success and not run.outcome.attack_success
    poisoned = [
        event for event in run.log.of_type(EventType.MEMORY_WRITE) if "partners@harbor" in event.payload["content"]
    ]
    assert poisoned and poisoned[0].payload["trust_level"] == "untrusted_external"
    blocked_external = [
        event
        for event in run.log.of_type(EventType.FIREWALL_DECISION)
        if "DESTINATION_NOT_AUTHORIZED" in event.payload["reason_codes"]
    ]
    assert blocked_external
    assert not run.log.of_type(EventType.APPROVAL_RECORD), "memory text must not mint protected approval records"


def test_guarded_executor_rejects_action_without_a_matching_decision() -> None:
    defense, state, _ = _bound("enterprise_direct_token_request")
    action = CandidateAction(
        type=ActionType.TOOL_CALL,
        tool="email_draft",
        arguments={
            "to": "nadia.khelifi@atlas.example",
            "subject": "Bypass",
            "body": "This did not pass the decision service.",
        },
    )
    preparation = defense.prepare_execution(action, step_id=1, timestamp=NOW)
    assert not preparation.permitted and preparation.error == "NO_MATCHING_DECISION"
    result = defense.execute_prepared(preparation, step_id=1, timestamp=NOW)
    assert not result.outcome.succeeded and state.table("drafts") == {}


def test_trace_verifier_rejects_receipt_action_digest_mismatch(run_config) -> None:  # type: ignore[no-untyped-def]
    run = run_scenario(load("enterprise_project_status"), SentinelFirewallDefense(), run_config)
    events = list(run.log.events)
    index = next(i for i, event in enumerate(events) if event.type is EventType.EXECUTOR_RECEIPT)
    payload = dict(events[index].payload)
    executed = dict(payload["executed_action"])
    executed["arguments"] = {"query": "tampered", "limit": 5}
    payload["executed_action"] = executed
    events[index] = events[index].model_copy(update={"payload": payload})
    with pytest.raises(TraceIntegrityError, match="does not match"):
        verify_digest_linked_trace(events)


def test_trace_verifier_accepts_repeated_identical_execution(run_config) -> None:  # type: ignore[no-untyped-def]
    run = run_scenario(load("enterprise_project_status"), SentinelFirewallDefense(), run_config)
    events = list(run.log.events)
    receipt = next(event for event in events if event.type is EventType.EXECUTOR_RECEIPT)
    digest = receipt.payload["action_digest"]
    repeated = [
        event
        for event in events
        if event.payload.get("action_digest") == digest
        and event.type
        in {
            EventType.ACTION_PROPOSAL,
            EventType.FIREWALL_DECISION,
            EventType.EXECUTOR_RECEIPT,
            EventType.STATE_VERIFIED,
        }
    ]
    next_seq = max(event.seq for event in events) + 1
    for offset, event in enumerate(repeated):
        events.append(event.model_copy(update={"seq": next_seq + offset, "event_id": f"repeat-{next_seq + offset}"}))

    report = verify_digest_linked_trace(events)

    assert report.executed_actions >= 3


def test_sentinel_refuses_legacy_scenario_without_task_authority(run_config) -> None:  # type: ignore[no-untyped-def]
    scenario = build_scenario()
    with pytest.raises(ValueError, match="task_authorization"):
        run_scenario(scenario, SentinelFirewallDefense(), run_config)
