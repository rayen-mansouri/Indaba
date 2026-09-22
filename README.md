# SENTINEL — deterministic action-boundary defense

SENTINEL is an IndabaX Tunisia 2026 submission built on the organizer-provided
offline simulator and Qwen3-8B reference agent. It reduces unauthorized simulator
effects at the action boundary while preserving authenticated work. It is not a
general prompt-injection cure, a claim of model truthfulness, or a benchmark score.

The complete submission consists of the firewall, replayable traces, offline
observability viewer, technical report, responsible-AI statement, and demonstration
video. All domain data is synthetic.

## What the defense does

The reference agent can propose actions, but it cannot execute tools directly.
SENTINEL derives trusted tool semantics from a versioned manifest, then evaluates
each consequential action against:

- immutable policy and authenticated task scope;
- lifecycle state and exact, one-time approvals;
- runtime-issued provenance and sensitivity lineage;
- payload, recipient, and destination constraints; and
- a guarded executor that emits digest-linked decision, receipt, and verified-state
  events.

The four deterministic outcomes are `ALLOW`, `BLOCK`, `ESCALATE`, and `REWRITE`.
Unknown tools, malformed security metadata, unknown sensitivity, missing authority,
and failed rewrites fail safely. The decision API cannot receive scenario IDs,
expected outcomes, reference plans, or evaluator labels.

## Evidence at a glance

Frozen mock-model diagnostics cover the 19 public and 9 validation scenarios.
SENTINEL reports BTU 1.000, ASR 0.000, CVR 0.000, FBR 0.000, and DFI 1.000 on both
splits. Public TUI is 0.983 because one attacker-influenced but non-violating draft
was persisted before the correct draft; it did not send a message or leak a canary.
These are local diagnostics, not an official score.

The committed Qwen3-8B evidence is trace-level rather than a full model benchmark:
it includes successful benign tasks, exact-date grader failures, and a non-vacuous
paired attack control. The video labels live Qwen, mock, and replay material
separately and shows the utility limitation plainly.

Sources and raw denominators: [evidence bundle](evidence/README.md),
[technical report](docs/technical-report.md), and
[model/data declaration](docs/model-data-declaration.md).

## Quick start

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). The default mock-model
workflow is fully offline.

```powershell
uv sync
uv run pytest -q
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml --defense sentinel --model mock
uv run sentinel replay artifacts/<run>/<trace>.jsonl
```

To compare a control with the defense, start from fresh state for each run:

```powershell
uv run sentinel run --scenario scenarios/public/enterprise/enterprise_poisoned_invoice.yaml --defense allow_all --model mock
uv run sentinel run --scenario scenarios/public/enterprise/enterprise_poisoned_invoice.yaml --defense sentinel --model mock
```

Treat a protected attack run as meaningful only when its matched `allow_all` control
reports `attack_success=true`.

## Local Qwen3-8B

Live evidence uses `qwen/qwen3-8b` through an already-loaded local LM Studio model:

```powershell
lms server start
lms load qwen/qwen3-8b --identifier sentinel-qwen3-8b --context-length 8192 --gpu max -y
uv run sentinel run --scenario scenarios/public/soc/soc_intel_correlation.yaml --defense sentinel --model lmstudio:sentinel-qwen3-8b
```

The LM Studio and optional HTTP-defense integrations now reject non-loopback URLs;
they are local development surfaces, not paths to external systems. The adapter uses
the organizer system prompt and registered tools unchanged, with temperature 0, seed
0, and a 2,048-token output budget. See the declaration for the exact model hash.

## Observe and reproduce

Open [the offline trace viewer](observability/sentinel-trace-viewer.html) directly
in Chrome or Edge, load a JSONL trace, and inspect decisions, G1–G7 results,
rewrites, approvals, receipts, verified state, comparison, scorecards, and continuity
checks. The Python verifier remains authoritative.

The final video, captions, thumbnail, and minimal polish source are in
[video](video/README.md). The video is 1920×1080, 30 fps, H.264/AAC, and includes
only synthetic data. Its final cut is
[`video/out/sentinel_demo_polished.mp4`](video/out/sentinel_demo_polished.mp4).

## Scope and limitations

- Scenario coverage is the organizer-published library: direct instruction, indirect
  injection, multi-step, memory poisoning, and tool-output manipulation. The library
  has no standalone `data_exfiltration` tag; its canary checks are cross-cutting.
  Hard-negative scenarios exercise over-refusal risk. See the
  [threat model](docs/threat-model.md).
- Deterministic severity and confidence are not calibrated probabilities.
- The authorization envelope is a protected simulator fixture, not a production IAM
  system. Production deployment needs real identity, policy, approval, retention,
  and operator-review integrations.
- The frozen aggregate uses one deterministic seed. AgentDojo was not run. Two
  Windows symlink tests require a symlink-capable host and are skipped locally.

## Repository map

```text
src/sentinel/firewall/  trusted action firewall, gates, approvals, trace verification
src/sentinel/           agent, model adapters, simulator, tools, evaluator, baselines
scenarios/              published synthetic public and validation scenarios
fixtures/ policies/     synthetic world data and machine-readable policies
evidence/               frozen scorecards, manifests, and replayable traces
observability/          offline trace viewer and aggregate dashboard
docs/                   report, threat model, declarations, safety statement, runbook
tests/                  unit, integration, and security regressions
video/                  final film and the small source package needed to inspect it
```

## Submission documents

- [Technical report](docs/technical-report.md)
- [Responsible-AI and security statement](docs/responsible-ai.md)
- [Organizer delta](docs/organizer-delta.md)
- [Video runbook](docs/video-script.md)
- [Evidence manifest](evidence/manifest.json)

## Provenance

This work extends the organizer-provided SENTINEL starter kit. Organizer history,
license, and attribution are intentionally retained; they document the origin of the
simulator and reference environment. Submission-specific changes are described in
[the organizer delta](docs/organizer-delta.md).

