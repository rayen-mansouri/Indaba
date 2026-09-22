from __future__ import annotations

import json

import httpx
import pytest

from sentinel.agent.base import AgentContext
from sentinel.models.base import TurnHints
from sentinel.models.hf_adapter import SYSTEM_PROMPT
from sentinel.models.lmstudio_adapter import LMStudioModelAdapter


def test_lmstudio_adapter_preserves_prompt_and_excludes_reference_plan() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"type":"respond","content":"ok","final":true}'}}]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    adapter = LMStudioModelAdapter(client=client)
    adapter.start_turn(
        "List the case",
        TurnHints(
            tools=[
                {
                    "name": "case_lookup",
                    "description": "Read a case",
                    "parameters": {
                        "type": "object",
                        "properties": {"case_id": {"type": "string"}},
                        "required": ["case_id"],
                    },
                    "consequential": False,
                }
            ],
            reference_plan=(),
        ),
    )

    action = adapter.propose(
        AgentContext(goal="List the case", turn_index=0, step_id=1, observations=[], provenance={}, tools=[])
    )

    assert action.content == "ok"
    messages = captured["messages"]
    assert isinstance(messages, list)
    assert messages[0] == {"role": "system", "content": SYSTEM_PROMPT}
    assert "List the case" in messages[1]["content"]
    assert '"case_id"' in messages[1]["content"]
    assert captured["temperature"] == 0
    assert captured["seed"] == 0
    assert captured["chat_template_kwargs"] == {"enable_thinking": False}
    assert "reference_plan" not in json.dumps(captured)


def test_lmstudio_adapter_rejects_non_local_endpoint() -> None:
    with pytest.raises(ValueError, match="loopback"):
        LMStudioModelAdapter(base_url="https://example.invalid/v1")
