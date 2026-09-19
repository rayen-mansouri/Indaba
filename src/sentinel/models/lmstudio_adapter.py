"""Local LM Studio adapter for the organizer-provided Qwen3-8B GGUF.

LM Studio is an inference runtime only.  This adapter deliberately reuses the exact system prompt,
action parser, context construction, and deterministic decode settings of the Hugging Face adapter.
It never sends evaluator metadata or the mock model's reference plan to the model.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from sentinel.agent.base import AgentContext, Feedback
from sentinel.core.actions import CandidateAction
from sentinel.models.base import ModelAdapter, ModelError, TurnHints
from sentinel.models.hf_adapter import SYSTEM_PROMPT, parse_action

DEFAULT_LMSTUDIO_MODEL = "sentinel-qwen3-8b"
DEFAULT_LMSTUDIO_URL = "http://127.0.0.1:1234/v1"


class LMStudioModelAdapter(ModelAdapter):
    """Call a locally loaded model through LM Studio's OpenAI-compatible endpoint."""

    name = "lmstudio"

    def __init__(
        self,
        model: str = DEFAULT_LMSTUDIO_MODEL,
        base_url: str = DEFAULT_LMSTUDIO_URL,
        max_tokens: int = 768,
        max_context_chars: int = 12_000,
        timeout_s: float = 180.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._max_tokens = max_tokens
        self._max_context_chars = max_context_chars
        self._client = client or httpx.Client(timeout=timeout_s)
        self._owns_client = client is None
        self._goal = ""
        self._tools: list[dict[str, Any]] = []

    def start_turn(self, goal: str, hints: TurnHints) -> None:
        self._goal = goal
        self._tools = hints.tools  # reference_plan is deliberately ignored

    def _messages(self, context: AgentContext) -> list[dict[str, str]]:
        history = "\n".join(f"[{obs.kind}] {obs.text}" for obs in context.observations)
        history = history[-self._max_context_chars :]
        tools = json.dumps(
            [{k: tool[k] for k in ("name", "description", "parameters", "consequential")} for tool in self._tools]
        )
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Tools: {tools}\nGoal: {self._goal}\nHistory:\n{history}"},
        ]

    def propose(self, context: AgentContext) -> CandidateAction:
        request = {
            "model": self._model,
            "messages": self._messages(context),
            "temperature": 0,
            "seed": 0,
            "max_tokens": self._max_tokens,
            "stream": False,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        try:
            response = self._client.post(f"{self._base_url}/chat/completions", json=request)
            response.raise_for_status()
            payload = response.json()
            content = payload["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise ModelError(f"LM Studio inference failed: {exc}") from exc
        if not isinstance(content, str):
            raise ModelError("LM Studio inference failed: response content is not text")
        return parse_action(content)

    def observe(self, feedback: Feedback) -> None:
        return None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
