import json
from pathlib import Path

import pytest

from sentinel.core.scenario import (
    ScenarioError,
    child_rng,
    child_seed,
    discover_scenarios,
    load_scenario,
    parse_scenario,
    scenario_json_schema,
)
from tests.conftest import PUBLIC, ROOT, minimal_scenario


def test_public_and_validation_counts() -> None:
    public = [load_scenario(p) for p in discover_scenarios(PUBLIC)]
    validation = [load_scenario(p) for p in discover_scenarios(ROOT / "scenarios" / "validation")]
    assert len(public) >= 19 and len(validation) >= 9
    # finance carries one extra scenario: the hand-authored difficulty-5 "long horizon" case.
    expected_counts = {"enterprise": 6, "finance": 7, "soc": 6}
    expected_indirect = {"enterprise": 1, "finance": 2, "soc": 1}
    for domain in ("enterprise", "finance", "soc"):
        items = [s for s in public if s.domain.value == domain]
        assert len(items) == expected_counts[domain]
        assert sum(s.is_benign and not s.is_hard_negative for s in items) == 2
        assert sum(s.is_hard_negative for s in items) == 1
        assert sum(s.attack.family.value == "direct_instruction" for s in items) == 1
        assert sum(s.attack.family.value == "indirect_prompt_injection" for s in items) == expected_indirect[domain]
        assert sum(s.attack.family.value in ("multi_step", "memory_poisoning") for s in items) == 1
    named = {s.id for s in public}
    assert {
        "enterprise_poisoned_invoice",
        "finance_false_approval",
        "soc_hostile_log_text",
        "enterprise_memory_poison",
        "finance_dormant_supplier_claim",
    } <= named
    assert any(s.attack.present and s.attack.difficulty == 5 for s in public), "no difficulty-5 scenario published"


def test_every_shipped_scenario_has_structured_authenticated_task_authority() -> None:
    scenarios = [load_scenario(path) for path in discover_scenarios(ROOT / "scenarios")]
    assert scenarios
    for scenario in scenarios:
        authority = scenario.task_authorization
        assert authority is not None, scenario.id
        assert authority.authenticated_by == "offline_simulator_identity"
        assert {grant.tool for grant in authority.grants} <= set(scenario.allowed_tools)
        serialized = authority.model_dump()
        assert not ({"scenario_id", "filename", "expected_outcome", "reference_plan"} & serialized.keys())


def test_task_authority_does_not_pin_reference_plan_derived_severity() -> None:
    scenarios = [load_scenario(path) for path in discover_scenarios(ROOT / "scenarios")]
    for scenario in scenarios:
        assert scenario.task_authorization is not None
        fields = {
            constraint.field
            for grant in scenario.task_authorization.grants
            for constraint in grant.parameters
        }
        assert "severity" not in fields, scenario.id


def test_minimal_scenario_parses() -> None:
    scenario = parse_scenario(minimal_scenario())
    assert scenario.is_benign and scenario.turns[0].reference_plan[-1].final


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"allowed_tools": ["email_search"]}, "not in allowed_tools"),
        ({"fixture": "../outside.json"}, "relative path"),
        ({"domain": "banking"}, "domain"),
        ({"seed": -1}, "seed"),
        ({"attack": {"present": True, "family": "direct_instruction", "objective": "x"}}, "security_properties"),
    ],
)
def test_actionable_errors(override: dict[str, object], message: str) -> None:
    with pytest.raises(ScenarioError) as info:
        parse_scenario(minimal_scenario(**override))
    assert message in str(info.value)


def test_attack_payload_must_reference_declared_surface() -> None:
    data = minimal_scenario(
        attack={
            "present": True,
            "family": "indirect_prompt_injection",
            "objective": "x",
            "surfaces": [
                {"id": "doc", "kind": "document", "target": "documents/DOC-3102/body", "operations": ["append_text"]}
            ],
            "payloads": [{"surface": "other", "operation": "append_text", "text": "hi"}],
        },
        security_properties=["no_forbidden_effect"],
    )
    with pytest.raises(ScenarioError, match="unknown surface"):
        parse_scenario(data)


def test_surface_operations_must_fit_kind() -> None:
    data = minimal_scenario(
        attack={
            "present": True,
            "family": "tool_output_manipulation",
            "objective": "x",
            "surfaces": [
                {
                    "id": "t",
                    "kind": "tool_output",
                    "target": "tool_output/ticket_read/latest_comment",
                    "operations": ["append_text"],
                }
            ],
        },
        security_properties=["no_forbidden_effect"],
    )
    with pytest.raises(ScenarioError, match="does not support"):
        parse_scenario(data)


def test_last_plan_step_must_be_final() -> None:
    data = minimal_scenario()
    data["turns"][0]["reference_plan"][-1]["final"] = False
    with pytest.raises(ScenarioError, match="final respond"):
        parse_scenario(data)


def test_load_rejects_unknown_extension(tmp_path: Path) -> None:
    path = tmp_path / "scenario.txt"
    path.write_text("id: x")
    with pytest.raises(ScenarioError, match=r"must be \.yaml"):
        load_scenario(path)


def test_json_scenarios_load(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    path.write_text(json.dumps(minimal_scenario()))
    assert load_scenario(path).id == "unit_minimal"


def test_schema_export_covers_core_fields() -> None:
    schema = scenario_json_schema()
    assert {"id", "turns", "attack", "success_conditions", "allowed_tools"} <= set(schema["properties"])


def test_child_rng_is_deterministic_and_label_scoped() -> None:
    assert child_seed(1, "a") == child_seed(1, "a")
    assert child_seed(1, "a") != child_seed(1, "b") != child_seed(2, "a")
    assert child_rng(5, "x").random() == child_rng(5, "x").random()
