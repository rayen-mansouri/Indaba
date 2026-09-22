import ast
from pathlib import Path

import httpx
import pytest

from sentinel.config import CompetitionConfig, DefenseRuntimeConfig, FailMode
from sentinel.core.actions import Decision
from sentinel.defenses.baselines import AllowAllDefense
from sentinel.defenses.client import DefenseUnavailable, HttpDefense
from sentinel.domains import DOMAIN_TOOLS
from sentinel.evaluator.runner import RunConfig, run_scenario
from sentinel.sandbox.submission import sample_defense_request
from sentinel.tools.base import ALLOWED_CAPABILITIES
from tests.conftest import ROOT, load

pytestmark = pytest.mark.security
SRC = ROOT / "src" / "sentinel"
NETWORK_MODULES = {"socket", "httpx", "requests", "urllib.request", "http.client", "subprocess", "aiohttp"}
NETWORK_WORDS = ("http", "url", "fetch", "browse", "web", "download", "shell", "socket")


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_no_network_tools_in_official_mode() -> None:
    assert "network" not in ALLOWED_CAPABILITIES
    for domain, factory in DOMAIN_TOOLS.items():
        for tool in factory():
            assert not any(word in tool.name for word in NETWORK_WORDS), (domain, tool.name)
            assert tool.capabilities <= ALLOWED_CAPABILITIES


def test_simulator_code_has_no_network_or_process_imports() -> None:
    simulator = [
        *(SRC / "domains").rglob("*.py"),
        *(SRC / "tools").rglob("*.py"),
        *(SRC / "core").rglob("*.py"),
        *(SRC / "agent").rglob("*.py"),
        *(SRC / "models" / "mock.py",),
        *(SRC / "evaluator").rglob("*.py"),
    ]
    for path in simulator:
        assert not imported_modules(path) & NETWORK_MODULES, path


def test_default_competition_is_fail_closed_and_offline() -> None:
    config = CompetitionConfig()
    assert config.official_mode and config.defense.fail_mode is FailMode.CLOSED


def test_canaries_detected_in_tool_arguments_and_outbound_messages(run_config: RunConfig) -> None:
    direct = run_scenario(load("enterprise_direct_token_request"), AllowAllDefense(), run_config).outcome
    sinks = {f["message"].split(" reached ")[1].split(" ")[0] for f in direct.findings if f["kind"] == "data_flow"}
    assert "email_send" in sinks  # outbound synthetic message
    invoice = run_scenario(load("enterprise_poisoned_invoice"), AllowAllDefense(), run_config).outcome
    assert any("email_draft" in f["message"] for f in invoice.findings if f["kind"] == "data_flow")  # tool args
    encoded = run_scenario(load("enterprise_val_encoded_exfil"), AllowAllDefense(), run_config).outcome
    assert any("encoding base64" in f["message"] for f in encoded.findings if f["kind"] == "data_flow")


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="not json"),
        httpx.Response(200, json={"decision": "maybe", "risk_score": 0.1, "confidence": 0.1}),
        httpx.Response(200, json={"decision": "allow", "risk_score": 7, "confidence": 0.1}),
        httpx.Response(200, json={"decision": "allow", "risk_score": 0.1, "confidence": 0.1, "chain_of_thought": "x"}),
        httpx.Response(200, json={"decision": "rewrite", "risk_score": 0.1, "confidence": 0.1}),
        httpx.Response(
            200, json={"decision": "allow", "risk_score": 0.1, "confidence": 0.1, "reason_codes": ["x" * 5]}
        ),
        httpx.Response(
            200,
            content=b'{"decision": "allow", "risk_score": 0, "confidence": 0, "explanation": "' + b"a" * 70_000 + b'"}',
        ),
        httpx.Response(302, headers={"location": "http://elsewhere.example/"}),
    ],
)
def test_malformed_participant_responses_are_rejected(response: httpx.Response) -> None:
    defense = HttpDefense("http://127.0.0.1", transport=httpx.MockTransport(lambda request: response), backoff_s=0)
    with pytest.raises(DefenseUnavailable):
        defense.decide(sample_defense_request())


def test_malformed_responses_fail_closed_in_a_run() -> None:
    defense = HttpDefense(
        "http://127.0.0.1",
        backoff_s=0,
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"oops": 1})),
    )
    config = RunConfig(
        root=ROOT, competition=CompetitionConfig(defense=DefenseRuntimeConfig(fail_mode=FailMode.CLOSED))
    )
    outcome = run_scenario(load("soc_hostile_log_text"), defense, config).outcome
    assert not outcome.attack_success
    assert all(d.decision is Decision.BLOCK for d in outcome.decisions)
