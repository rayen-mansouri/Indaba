import json

import pytest
from pydantic import ValidationError

from sentinel.core.actions import ActionType, CandidateAction
from sentinel.core.policies import load_policy
from sentinel.core.provenance import TrustLevel
from sentinel.firewall.policy import PolicySnapshot
from sentinel.firewall.records import (
    EVALUATOR_ONLY_FIELDS,
    AuthenticatedPrincipal,
    CapabilityGrant,
    DecisionContext,
    NormalizedAction,
    TaskScope,
    WorkflowState,
)
from sentinel.firewall.toolspecs import ApprovalRule, build_official_tool_manifest
from sentinel.tools.registry import registry_for_domain
from tests.conftest import ROOT


def _scope() -> TaskScope:
    return TaskScope(
        task_id="task-1",
        principal=AuthenticatedPrincipal(
            principal_id="operator-1",
            role="operator",
            authenticated_by="simulator_identity",
        ),
        grants=(CapabilityGrant(tool="asset_lookup", capabilities=("read",), resources=("WS-12",)),),
        issued_state_version=0,
    )


def _candidate() -> NormalizedAction:
    action = CandidateAction(type=ActionType.TOOL_CALL, tool="asset_lookup", arguments={"asset_id": "WS-12"})
    return NormalizedAction(
        raw_proposal=action,
        executable=action,
        tool_spec_version="1.0.0",
        normalizer_version="sentinel-c14n/1",
        action_digest=action.digest(),
    )


def test_manifest_covers_every_registered_tool_with_strict_schema() -> None:
    manifest = build_official_tool_manifest()
    registered = {tool.name for domain in ("enterprise", "finance", "soc") for tool in registry_for_domain(domain)}
    assert {spec.name for spec in manifest.specs} == registered
    assert len(manifest.specs) == 25
    for spec in manifest.specs:
        schema = json.loads(spec.strict_schema_json)
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert spec.version == "1.0.0"
        assert spec.normalizer_version == manifest.normalizer_version


def test_manifest_has_dynamic_and_always_approval_semantics() -> None:
    manifest = build_official_tool_manifest()
    assert manifest.get("email_send").approval_rule is ApprovalRule.ALWAYS  # type: ignore[union-attr]
    incident = manifest.get("incident_update")
    assert incident is not None
    assert incident.approval_rule is ApprovalRule.CONDITIONAL
    assert incident.approval_field == "status"
    assert incident.approval_values == ("closed",)


def test_manifest_hash_is_stable_and_detects_tampering() -> None:
    first = build_official_tool_manifest()
    second = build_official_tool_manifest()
    assert first.manifest_hash == second.manifest_hash
    with pytest.raises(ValidationError, match="manifest hash"):
        first.model_copy(update={"manifest_hash": "0" * 64}).__class__.model_validate(
            first.model_dump() | {"manifest_hash": "0" * 64}
        )


def test_policy_snapshot_is_run_and_manifest_bound() -> None:
    manifest = build_official_tool_manifest()
    policy = load_policy(ROOT, "finance_standard")
    allowed = ("payment_prepare", "payment_confirm")
    first = PolicySnapshot.capture("run-1", policy, manifest, allowed)
    again = PolicySnapshot.capture("run-1", policy, manifest, allowed)
    other_run = PolicySnapshot.capture("run-2", policy, manifest, allowed)
    assert first.policy_hash == again.policy_hash
    assert first.policy_hash != other_run.policy_hash
    with pytest.raises(ValidationError):
        PolicySnapshot.model_validate(first.model_dump() | {"policy_version": 2})


def test_decision_context_structurally_rejects_evaluator_metadata() -> None:
    payload = {
        "run_id": "run-1",
        "session_id": "session-1",
        "step_id": 1,
        "live_agent_state": WorkflowState(version=0),
        "candidate": _candidate(),
        "provenance": (),
        "active_policy_hash": "a" * 64,
        "task_scope": _scope(),
    }
    DecisionContext.model_validate(payload)
    assert not EVALUATOR_ONLY_FIELDS.intersection(DecisionContext.model_fields)
    for forbidden in EVALUATOR_ONLY_FIELDS:
        with pytest.raises(ValidationError):
            DecisionContext.model_validate(payload | {forbidden: "forbidden"})


def test_task_scope_is_structured_and_immutable() -> None:
    scope = _scope()
    assert scope.grant_for("asset_lookup") is not None
    assert scope.grant_for("remediation_execute") is None
    with pytest.raises(ValidationError):
        CapabilityGrant(tool="payment_prepare", max_amount=1000)
    with pytest.raises(ValidationError):
        TaskScope.model_validate(scope.model_dump() | {"scenario_id": "soc_hostile_log_text"})
    with pytest.raises(ValidationError):
        scope.task_id = "changed"  # type: ignore[misc]


def test_normalized_action_rejects_digest_mismatch() -> None:
    data = _candidate().model_dump()
    with pytest.raises(ValidationError, match="action_digest"):
        NormalizedAction.model_validate(data | {"action_digest": "wrong"})


def test_public_trust_labels_remain_exactly_the_starter_contract() -> None:
    assert {label.value for label in TrustLevel} == {
        "system_policy",
        "authenticated_user",
        "trusted_internal",
        "untrusted_internal",
        "untrusted_external",
        "adversary_controlled",
    }
