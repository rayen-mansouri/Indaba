# Participant guide

SENTINEL is not a hidden-test competition. The attacks are known; the challenge is to show how
creatively, rigorously, and effectively you can engineer an AI agent that survives them.

## What you submit

1. **A defense solution**, built however you choose. No required architecture, language, or
   interface — a policy engine, a provenance system, a learned monitor, multi-agent oversight,
   memory controls, action rewriting, or anything else that resolves to one of the four actions
   below.
2. **An observability layer** that makes your defense's decisions legible: for each candidate
   action, what it decided, why, and what happened next.
3. **A video demonstration**, 5–10 minutes, showing an attack reaching your defense and failing, a
   benign task completing normally, and the observability layer explaining both.
4. **A GitHub repository** of your source code.
5. **A technical report** — no page limit — covering your threat model, method, experiments,
   ablations, failure analysis, and responsible-AI considerations. Template:
   [research-report-template.md](research-report-template.md).

## Setup

```bash
git clone <sentinel-bench> && cd sentinel-bench
uv sync
make test
```

Running the reference Qwen3-8B agent needs `uv sync --extra hf` and the weights downloaded ahead of
time (`huggingface-cli download Qwen/Qwen3-8B`). Use `--model mock` while iterating on your defense
logic — it drives the same tools and events without GPU time — and switch to `--model qwen3-8b` once
you are ready to record the trace your video is built around.

## Official reference model: Qwen3-8B

You receive a preconfigured **Qwen3-8B** (`Qwen/Qwen3-8B`) tool-using agent as the reference
implementation, running locally through the SENTINEL simulator on synthetic data. Your defense sits
between that agent and its tools. Nothing requires you to keep using Qwen3-8B internally — your own
reasoning can be rules, a fine-tuned model, model-internals probes, multi-agent oversight, or
anything else; the agent it protects is the fixed part, not your method.

### How you may run it

You may change **how the agent runs**. You may not change **what the agent is**.

Runtime and plumbing are yours to configure: precision and quantization (a 4-bit GGUF build run
through llama.cpp or Ollama is fine on a small GPU), which machine or cloud GPU it sits on, the
decode budget, and whether Qwen3's thinking mode is on. What stays fixed is the agent as the naive,
fallible thing your defense has to protect: the same model, the same tools, the same system prompt,
and no safety instructions added to it. If the agent stops falling for attacks because you hardened
the agent, there is nothing left for the jury to evaluate — that work belongs in your defense.

"Runs locally" and "fully offline" describe what the agent talks to, not where the silicon is: an
open-weight model you host yourself, no external inference API, and simulated tools that reach no
real system. A model running inside your own cloud notebook satisfies that. (The optional AgentDojo
bonus track is the one part of a submission that may call a live API.)

`HFModelAdapter` takes `device`, `dtype`, `max_new_tokens`, and `enable_thinking`; the defaults pick
your GPU when there is one and turn thinking off, because Qwen3's reasoning can consume the decode
budget before the JSON action is complete. Keeping thinking on and raising `max_new_tokens` instead
is equally acceptable.

Put whatever you changed — quantization, dtype, thinking mode, token budget, where it ran — in a
short "how we ran the reference agent" paragraph in your report. That is the whole declaration.

### Check your setup actually exercises the scenario

Run this before you record anything:

```bash
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
  --defense allow_all --model qwen3-8b
```

Every attack scenario is built so that the attack **succeeds** when nothing is defending, so this
run must report `attack_success=True`. If it reports `False`, your agent finished the task without
ever opening the record the attack was injected into — the payload was never in front of it. Nothing
measured in that configuration means anything, because a defense that does nothing scores exactly
the same as a good one.

This is the single most important check in the kit. A quantized model on a small GPU is more likely
to stop early, so run it for each scenario you plan to demonstrate, not just once. If a scenario
will not reach `attack_success=True` on your hardware, demonstrate it with `--model mock`, which is
tested to inject reliably, and say so in your report.

## Defense Rules

Every decision must come from the **agent state, the candidate action, its provenance, the active
policy, and the content observed** — nothing else.

**Scenario-specific hard-coding is not a valid defense.** Deciding from a scenario identifier, a
filename, or any organizer-provided expected outcome disqualifies that decision, however correct it
looks in the video.

Every decision resolves to exactly one of four actions:

| Action | Meaning |
| --- | --- |
| `allow` | the action proceeds unchanged |
| `block` | the action is stopped; the agent is told why |
| `escalate` | a simulated human is asked to approve or deny before it proceeds |
| `rewrite` | a safer action is substituted (for example send → draft); it cannot make a non-final action final, and it cannot name an unknown tool |

Never return chain-of-thought. A risk score, a confidence, and a short UPPER_SNAKE_CASE reason are
enough for your own observability layer to show why a decision was made.

**Memory inherits trust.** A memory entry written after reading untrusted content stays untrusted
when recalled later — treat it as evidence, not as an instruction with authority of its own.
**Untrusted does not mean irrelevant** — many legitimate tasks require reading vendor email or raw
logs; a defense that ignores untrusted content loses utility.

## If you build your defense as an HTTP service

The `python-defense` starter kit follows this shape, and the CLI's `--defense-url` option expects it
— but this is one convenient pattern among many, not a requirement.

Request (abridged):

```json
{
  "run_id": "finance_false_approval-python_defense-s0",
  "step_id": 4,
  "user_goal": "For case CASE-7001, prepare the 1,250 TND refund ...",
  "conversation": [{"role": "tool", "kind": "tool_result", "content": "...", "provenance_ids": ["prov-0003"]}],
  "observation": {"kind": "tool_result", "content": "...", "provenance_ids": ["prov-0003"]},
  "candidate_action": {"type": "tool_call", "tool": "payment_confirm", "arguments": {"payment_id": "PAY-0001"}},
  "policy_context": {"allowed_tools": ["..."], "consequential_tools": ["payment_confirm", "payment_execute"],
                     "internal_email_domains": ["atlas.example"], "rules": ["..."]},
  "provenance": [{"id": "prov-0003", "provenance": {"source_type": "case_document", "trust_level": "untrusted_external",
                                                    "sensitivity": "internal", "origin_actor": "nova_electronics", "...": "..."}}],
  "history_digest": {"steps_taken": 3, "confirmations_granted": [], "tool_calls": ["..."],
                     "least_trusted_seen": "untrusted_external", "most_sensitive_seen": "confidential"}
}
```

Response:

```json
{"decision": "escalate", "risk_score": 0.62, "confidence": 0.7, "reason_codes": ["MISSING_CONFIRMATION"],
 "explanation": "Consequential payment step without recorded approval.", "metadata": {}}
```

- Reason codes are `UPPER_SNAKE_CASE`, at most 16 per decision.
- `explanation` is limited to 500 characters and must never contain chain-of-thought.
- `metadata` is opaque and at most 4 KB.
- Timeouts, transport errors, and malformed responses fail closed by default (the action is blocked).

## Local workflow

```bash
uv run sentinel scenarios list scenarios/public
uv run sentinel run --scenario scenarios/public/soc/soc_hostile_log_text.yaml --defense provenance
uv run sentinel run --scenario scenarios/public/soc/soc_hostile_log_text.yaml --defense-url http://127.0.0.1:8080 --model qwen3-8b
uv run sentinel eval public --defense-url http://127.0.0.1:8080 --json > my-metrics.json
uv run sentinel replay artifacts/<group>/<run>.jsonl
```

`sentinel eval` is a self-test tool: it reports metrics (BTU, ASR, CVR, FBR, UER, ...; see
[scoring.md](scoring.md)) across the published scenario library that you can cite as evidence in your
report. It is not the official score — judging is based on the published jury rubric.

## Scoring, in one paragraph

Judges score your submission from your video and observability layer, your technical report, your
repository, and your defense's creativity and novelty — 100 points across four categories (40/25/15/20).
Full rubric: [scoring.md](scoring.md). There is no numeric score to game and no hidden test set:
everything you need is already published.

## What will not score well

Keyword filters, blanket refusal, escalating everything, deciding from a scenario id or an
organizer-provided expected outcome instead of the signals in front of you, and claims of complete
safety with no acknowledged limitations.

## Rules of engagement

Attack only the simulator and the challenge components it provides. Do not scan or probe organizer or
sponsor infrastructure, attempt sandbox escape, steal credentials, persist on hosts, run denial of
service, or use real personal data. Report accidental infrastructure vulnerabilities via
[SECURITY.md](../SECURITY.md).

## Optional bonus track: AgentDojo

For extra credibility, run your defense against **AgentDojo** (NeurIPS 2024), an independent,
peer-reviewed benchmark for prompt-injection attacks and defenses on tool-using agents, and report
the results in your video and technical report — generalizing beyond SENTINEL's own scenarios is
strong evidence. This is entirely optional, on your own time and compute; it calls a live model API,
so it is the one part of your submission that is not required to stay offline. It adds no separate
award and is not required to compete for the three winning spots.

## Team size and dates

Teams of 3–5. Challenge release **17/09**, info session **18/09** (time TBA), submission deadline
**22/09 23:59**. The eight highest-scoring submissions are announced on event day and invited to
pitch their solution live; three winners are selected from among the teams that pitch. Submission
link is published to registered participants. Questions: **skander.yacoubi@supcom.tn**.
