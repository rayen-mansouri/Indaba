# Python defense starter kit

**Optional.** SENTINEL does not require a specific architecture, language, or interface — you may
build your solution however you choose (see
[Defense Rules](../../docs/participant-guide.md#defense-rules) in the participant guide). This kit
is one example: a defense exposed as an HTTP service, following the same shape the CLI's
`--defense-url` option expects. Copy it, change `app/decision.py`, and you have a working starting
point — or ignore it entirely and build your own.

```
python-defense/
├── app/models.py        # example request/response shapes (self-contained; no sentinel import needed)
├── app/decision.py      # <- your defense logic
├── app/main.py          # FastAPI service: GET /healthz, POST /v1/decision
├── tests/test_app.py
├── Dockerfile           # non-root, port 8080
└── sentinel-submission.yaml
```

## What you are defending

Participants get a preconfigured **Qwen3-8B** tool-using agent as the official reference
implementation (`Qwen/Qwen3-8B`), running locally through the SENTINEL simulator on synthetic data.
Your defense sits between that agent and its tools. Nothing here requires you to keep using Qwen3-8B
internally — your reasoning can be rules, a fine-tuned model, model-internals probes, multi-agent
oversight, or anything else; the agent it protects is the fixed part, not your method.

## Develop

```bash
cp -r starter-kits/python-defense ../my-defense
cd ../my-defense
uv venv && uv pip install -r requirements.txt pytest httpx
uv run pytest -q
uv run uvicorn app.main:app --port 8080
```

## Try it against the reference agent

In another shell, from the `sentinel-bench` checkout:

```bash
# the reference agent (Qwen3-8B) proposes actions; your service decides on them
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
  --defense-url http://127.0.0.1:8080 --model qwen3-8b

# replay the trace -- this is the evidence your video is built around
uv run sentinel replay artifacts/<group>/<run>.jsonl
```

`--model qwen3-8b` needs the weights downloaded ahead of time (`uv sync --extra hf`, then
`huggingface-cli download Qwen/Qwen3-8B`) and enough local compute to run an 8B model. Use
`--model mock` while iterating on your defense logic itself -- it drives the same tools and events
without needing GPU time, so you can develop the decision logic first and validate against Qwen3-8B
once it is behaving the way you expect.

## Validate and containerize

```bash
uv run sentinel submission validate ../my-defense
docker build -t my-defense:dev ../my-defense
docker run --rm -p 127.0.0.1:8080:8080 --read-only --tmpfs /tmp --cap-drop ALL my-defense:dev
uv run sentinel submission validate my-defense:dev --live-url http://127.0.0.1:8080
```

## Reminders

- Reason from the agent state, the candidate action, its provenance, the active policy, and the
  content observed -- never from a scenario identifier or a hard-coded expected outcome.
- Every decision resolves to one of four outcomes: `allow`, `block`, `escalate`, or `rewrite`.
  `rewrite` must include a `rewritten_action`; it may not turn a non-final action into a final one.
- Reason codes are `UPPER_SNAKE_CASE`. Never return private chain-of-thought -- a risk score, a
  confidence, and a short reason are enough for your own observability layer to show why.
- There is no automated benchmark and no numeric score to game. Judges watch your video and the
  trace it is built around, read your technical report, and read your code.
