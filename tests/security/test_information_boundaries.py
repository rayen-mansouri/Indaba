import json

import pytest

from sentinel.attackers.baselines import StaticAttacker
from sentinel.attackers.interface import Attacker, AttackMutation, AttackRequest
from sentinel.core.actions import Decision, DefenseDecision
from sentinel.defenses.baselines import AllowAllDefense
from sentinel.defenses.interface import Defense, DefenseRequest
from sentinel.evaluator.runner import RunConfig, load_suite, run_scenario
from tests.conftest import PUBLIC, ROOT, load

pytestmark = pytest.mark.security

HIDDEN_KEYS = {
    "reference_plan",
    "success_conditions",
    "security_properties",
    "forbidden_effects",
    "payloads",
    "legitimate",
    "match_keys",
    "human_oracle",
    "grader_results",
    "canaries",
}


def test_firewall_decision_code_does_not_read_evaluator_canary_registry() -> None:
    runtime = (ROOT / "src" / "sentinel" / "firewall" / "runtime.py").read_text(encoding="utf-8")
    assert ".canaries" not in runtime


class Capture(Defense):
    name = "capture"

    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        self.requests.append(request.model_dump(mode="json"))
        return AllowAllDefense().decide(request)


def keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in keys(v)}
    return set()


def test_defense_requests_never_contain_ground_truth(run_config: RunConfig) -> None:
    for scenario in load_suite(PUBLIC):
        capture = Capture()
        run_scenario(scenario, capture, run_config)
        assert capture.requests
        for request in capture.requests:
            assert not keys(request) & HIDDEN_KEYS
            text = json.dumps(request)
            assert scenario.attack.objective == "" or scenario.attack.objective not in text
            for condition in scenario.success_conditions:
                assert json.dumps(condition.model_dump()) not in text


def test_canary_values_only_appear_after_the_agent_reads_them(run_config: RunConfig) -> None:
    capture = Capture()
    run = run_scenario(load("enterprise_project_status"), capture, run_config)
    assert run.outcome.task_success
    text = json.dumps(capture.requests)
    assert "SENTINEL_SECRET_" not in text and "CTR-SYN-" not in text


def test_attack_requests_expose_only_bounded_state(run_config: RunConfig) -> None:
    seen: list[AttackRequest] = []

    class Spy(Attacker):
        def next_mutation(self, request: AttackRequest) -> AttackMutation | None:
            seen.append(request)
            return StaticAttacker().next_mutation(request)

    run_scenario(load("enterprise_poisoned_invoice"), AllowAllDefense(), run_config, Spy())
    assert seen
    for request in seen:
        dumped = request.model_dump(mode="json")
        assert not keys(dumped) & (HIDDEN_KEYS - {"payloads"})
        assert set(dumped) == {
            "scenario_id",
            "domain",
            "round",
            "step_id",
            "objective",
            "surfaces",
            "transcript",
            "seed_payloads",
            "budget_remaining",
        }
        assert all(len(s["current_text"]) <= 1200 for s in dumped["surfaces"])
        assert "SENTINEL_SECRET_" not in json.dumps(dumped)


def test_defense_metadata_cannot_change_evaluator_results(run_config: RunConfig) -> None:
    class Liar(Defense):
        name = "liar"

        def decide(self, request: DefenseRequest) -> DefenseDecision:
            return DefenseDecision(
                decision=Decision.ALLOW,
                risk_score=0.0,
                confidence=1.0,
                metadata={
                    "task_success": True,
                    "attack_success": False,
                    "btu": 1.0,
                    "critical_violation": False,
                    "legitimate": True,
                },
            )

    honest = run_scenario(load("finance_false_approval"), AllowAllDefense(), run_config).outcome
    lying = run_scenario(load("finance_false_approval"), Liar(), run_config).outcome
    assert lying.attack_success and lying.critical_violation and not lying.task_success

    def strip(findings: list[dict[str, object]]) -> list[dict[str, object]]:
        return [{k: v for k, v in f.items() if k != "event_ref"} for f in findings]  # event ids embed the run id

    assert strip(lying.findings) == strip(honest.findings)
    assert "metadata" not in lying.model_dump()["decisions"][0]


def test_oversized_or_invalid_metadata_is_rejected_by_contract() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        DefenseDecision(decision=Decision.ALLOW, risk_score=0, confidence=0, metadata={"x": "y" * 10_000})
    with pytest.raises(ValueError, match="JSON-serializable"):
        DefenseDecision(decision=Decision.ALLOW, risk_score=0, confidence=0, metadata={"x": object()})


def test_artifacts_contain_no_reference_plans(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from sentinel.storage.runs import ArtifactStore, read_events

    config = RunConfig(root=ROOT, artifacts=ArtifactStore(tmp_path), artifact_group="g")
    run = run_scenario(load("enterprise_memory_poison"), AllowAllDefense(), config)
    assert run.artifact is not None
    for event in read_events(run.artifact):
        assert not keys(event.payload) & {"reference_plan", "success_conditions", "match_keys"}
