import pytest

from sentinel.core.canary import CanaryRegistry
from sentinel.core.scenario import CanarySpec
from sentinel.core.state import StateError, WorldState, resolve_within
from tests.conftest import ROOT, build_scenario, state_for


def test_canaries_are_seeded_and_substituted() -> None:
    first = state_for("enterprise_poisoned_invoice")
    again = state_for("enterprise_poisoned_invoice")
    other_run = state_for("enterprise_poisoned_invoice", run_seed=1)
    token = first.canaries.canaries["vendor_portal_token"].value
    assert token.startswith("SENTINEL_SECRET_")
    assert token == again.canaries.canaries["vendor_portal_token"].value
    assert token != other_run.canaries.canaries["vendor_portal_token"].value
    wiki = first.get("wiki", "WK-001")
    assert wiki is not None and token in wiki["content"] and "{{canary" not in wiki["content"]


def test_undeclared_canary_is_rejected() -> None:
    registry = CanaryRegistry.from_specs(1, [CanarySpec(name="known", kind="secret_token")])
    with pytest.raises(KeyError, match="undeclared"):
        registry.substitute("{{canary:unknown}}")


def test_extra_records_are_merged_and_ids_unique() -> None:
    record = {
        "id": "EM-9999",
        "from": "a@atlas.example",
        "to": "b@atlas.example",
        "subject": "s",
        "body": "b",
        "_meta": {"source_type": "email", "trust_level": "trusted_internal", "origin_actor": "x"},
    }
    scenario = build_scenario(extra_records={"emails": [record]})
    state = WorldState.from_scenario(scenario, ROOT)
    assert state.get("emails", "EM-9999") is not None
    duplicate = build_scenario(extra_records={"emails": [dict(record, id="EM-2001")]})
    with pytest.raises(StateError, match="duplicate id"):
        WorldState.from_scenario(duplicate, ROOT)


def test_resolve_within_blocks_traversal(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assert resolve_within(tmp_path, "a/b.json") == (tmp_path / "a/b.json").resolve()
    with pytest.raises(StateError):
        resolve_within(tmp_path, "../escape.json")
    with pytest.raises(StateError):
        resolve_within(tmp_path, "/etc/passwd")


def test_find_is_case_and_type_tolerant() -> None:
    state = state_for("finance_false_approval")
    assert state.find("customers", {"name": "salma ferchichi"})
    assert not state.find("customers", {"name": "nobody"})


def test_snapshot_cannot_mutate_authoritative_state() -> None:
    state = state_for("finance_false_approval")
    snapshot = state.snapshot()
    snapshot["collections"].clear()
    assert state.collections
