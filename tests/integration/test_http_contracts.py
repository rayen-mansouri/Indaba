import json
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from sentinel.api.defense_app import create_defense_app
from sentinel.config import CompetitionConfig, DefenseRuntimeConfig, FailMode
from sentinel.core.actions import Decision
from sentinel.defenses.baselines import ProvenanceDefense
from sentinel.defenses.client import DefenseUnavailable, HttpDefense
from sentinel.evaluator.runner import RunConfig, evaluate, load_suite, run_scenario
from sentinel.sandbox.submission import sample_defense_request, validate_submission
from tests.conftest import PUBLIC, ROOT, load, tool_call
from tests.integration.helpers import free_port, serve

pytestmark = pytest.mark.integration


def test_http_defense_matches_in_process_results(run_config: RunConfig) -> None:
    suite = load_suite(PUBLIC)
    local = evaluate(suite, ProvenanceDefense, run_config)
    with serve(create_defense_app(ProvenanceDefense())) as url:
        remote = evaluate(suite, lambda: HttpDefense(url), run_config)
    strip = ("latency_median_ms", "latency_p95_ms")
    assert {k: v for k, v in local.metrics.model_dump().items() if k not in strip} == {
        k: v for k, v in remote.metrics.model_dump().items() if k not in strip
    }
    assert remote.metrics.defense_errors == 0


def test_transport_failures_are_retried_but_bad_responses_are_not() -> None:
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("down", request=request)
        return httpx.Response(200, json={"decision": "allow", "risk_score": 0.1, "confidence": 0.9})

    defense = HttpDefense("http://127.0.0.1", transport=httpx.MockTransport(flaky), transport_retries=2, backoff_s=0)
    assert defense.decide(sample_defense_request()).decision is Decision.ALLOW and calls["n"] == 3

    errors = {"n": 0}

    def server_error(request: httpx.Request) -> httpx.Response:
        errors["n"] += 1
        return httpx.Response(500)

    broken = HttpDefense("http://127.0.0.1", transport=httpx.MockTransport(server_error), backoff_s=0)
    with pytest.raises(DefenseUnavailable, match="HTTP 500"):
        broken.decide(sample_defense_request())
    assert errors["n"] == 1
    assert broken.decide_or_fallback(sample_defense_request()).decision is Decision.BLOCK


def test_unreachable_defense_fails_closed() -> None:
    url = f"http://127.0.0.1:{free_port()}"
    config = RunConfig(
        root=ROOT,
        competition=CompetitionConfig(
            defense=DefenseRuntimeConfig(fail_mode=FailMode.CLOSED, transport_retries=0, timeout_s=1)
        ),
    )
    outcome = run_scenario(load("finance_false_approval"), HttpDefense(url, transport_retries=0), config).outcome
    assert not outcome.attack_success and not outcome.task_success
    assert all(d.decision is Decision.BLOCK and d.defense_error == "DefenseUnavailable" for d in outcome.decisions)


def test_live_submission_contract_checks() -> None:
    with serve(create_defense_app(ProvenanceDefense())) as url:
        report = validate_submission(str(ROOT / "starter-kits" / "python-defense"), live_url=url)
        assert report.ok, report.to_dict()


def test_participant_starter_kit_end_to_end(run_config: RunConfig) -> None:
    kit = ROOT / "starter-kits" / "python-defense"
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=kit,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                if httpx.get(f"{url}/healthz").status_code == 200:
                    break
            except httpx.TransportError:
                time.sleep(0.1)
        report = evaluate(load_suite(PUBLIC), lambda: HttpDefense(url), run_config)
        assert report.metrics.defense_errors == 0
        assert report.metrics.btu is not None and report.metrics.btu >= 0.5
        assert report.metrics.asr is not None and report.metrics.asr < 1.0
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_starter_kit_digest_matches_evaluator() -> None:
    action = tool_call("payment_confirm", payment_id="PAY-0001", amount=12.0, note="a  b")
    code = (
        "import json, sys\nfrom app.decision import action_digest\nfrom app.models import CandidateAction\n"
        "print(action_digest(CandidateAction.model_validate(json.loads(sys.argv[1]))))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, json.dumps(action.model_dump(mode="json"))],
        cwd=ROOT / "starter-kits" / "python-defense",
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == action.digest()


def test_starter_models_accept_real_requests(run_config: RunConfig, tmp_path: Path) -> None:
    captured: list[str] = []

    class Capture(ProvenanceDefense):
        def decide(self, request):  # type: ignore[no-untyped-def]
            captured.append(request.model_dump_json())
            return super().decide(request)

    run_scenario(load("enterprise_memory_poison"), Capture(), run_config)
    data = tmp_path / "requests.json"
    data.write_text(json.dumps(captured))
    code = (
        "import json, sys\nfrom app.models import DefenseRequest\n"
        "[DefenseRequest.model_validate_json(r) for r in json.load(open(sys.argv[1]))]\nprint('ok')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(data)],
        cwd=ROOT / "starter-kits" / "python-defense",
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "ok"
