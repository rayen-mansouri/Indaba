"""HTTP client for participant defense services, plus fail-mode handling."""

from __future__ import annotations

import time

import httpx
from pydantic import ValidationError

from sentinel.config import FailMode
from sentinel.core.actions import Decision, DefenseDecision
from sentinel.core.local_transport import require_loopback_url
from sentinel.defenses.interface import Defense, DefenseRequest

MAX_RESPONSE_BYTES = 64_000


class DefenseUnavailable(RuntimeError):
    """Transport failure, timeout, bad status, or a malformed response."""


def fail_mode_decision(fail_mode: FailMode, error: str) -> DefenseDecision:
    kind = Decision.BLOCK if fail_mode is FailMode.CLOSED else Decision.ALLOW
    return DefenseDecision(
        decision=kind,
        risk_score=1.0 if kind is Decision.BLOCK else 0.0,
        confidence=0.0,
        reason_codes=["DEFENSE_UNAVAILABLE"],
        explanation=f"defense unavailable ({fail_mode.value} fail mode): {error[:200]}",
    )


class HttpDefense(Defense):
    """Calls ``POST /v1/decision``. Retries transport failures only; never retries bad responses.

    ``decide`` raises DefenseUnavailable so the evaluator can record the error and apply the
    configured fail mode. ``decide_or_fallback`` applies the fail mode directly.
    """

    def __init__(
        self,
        base_url: str,
        timeout_s: float = 5.0,
        transport_retries: int = 2,
        fail_mode: FailMode = FailMode.CLOSED,
        name: str = "http_defense",
        transport: httpx.BaseTransport | None = None,
        backoff_s: float = 0.05,
    ) -> None:
        self.name = name
        self.fail_mode = fail_mode
        self.transport_retries = transport_retries
        self.backoff_s = backoff_s
        self._client = httpx.Client(
            base_url=require_loopback_url(base_url, label="defense URL"),
            timeout=timeout_s,
            transport=transport,
            follow_redirects=False,
        )

    def health(self) -> bool:
        try:
            return self._client.get("/healthz").status_code == 200
        except httpx.TransportError:
            return False

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        payload = request.model_dump(mode="json")
        last_error: Exception | None = None
        for attempt in range(self.transport_retries + 1):
            try:
                response = self._client.post("/v1/decision", json=payload)
                break
            except httpx.TransportError as exc:
                last_error = exc
                if attempt < self.transport_retries:
                    time.sleep(self.backoff_s * (attempt + 1))
        else:
            raise DefenseUnavailable(f"transport failure: {type(last_error).__name__}")
        if response.status_code != 200:
            raise DefenseUnavailable(f"HTTP {response.status_code}")
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise DefenseUnavailable("response too large")
        try:
            return DefenseDecision.model_validate_json(response.content)
        except ValidationError as exc:
            raise DefenseUnavailable(f"malformed decision: {exc.errors()[0]['msg']}") from exc

    def decide_or_fallback(self, request: DefenseRequest) -> DefenseDecision:
        try:
            return self.decide(request)
        except DefenseUnavailable as exc:
            return fail_mode_decision(self.fail_mode, str(exc))

    def close(self) -> None:
        self._client.close()
