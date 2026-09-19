# SENTINEL Team Handoff

## Current state

- Active phase: Phase 2/3 — live deterministic core integration; Qwen3-8B exit still open.
- Official starter revision: `87944a1bbb4565fac853e017dac2727b0f377704`.
- Remotes: `upstream` is `Skan22/Sentinel_Starter_Kit`; `origin` is `rayen-mansouri/Indaba`.
- Mock-model baseline: verified with run ID `finance_false_approval-provenance-s0`.
- Live firewall: `--defense sentinel` is registered and uses guarded execution, exact approvals,
  safe rewrite revalidation, and digest-linked trace events. All 28 shipped scenarios carry
  explicit authenticated task grants. The complete public and validation libraries pass with the
  mock model; Qwen3-8B remains open.

## Verified setup and commands

```powershell
uv sync
uv run pytest
uv run --project . pytest -q starter-kits/python-defense/tests
uv run --project . pytest -q starter-kits/learned-monitor/tests
uv run sentinel scenarios list scenarios --json
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml --defense provenance
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml --defense sentinel
uv run sentinel replay artifacts/<group>/<run>.jsonl
```

GNU Make was not installed on the audited Windows host, so the exact commands in its targets were
run directly. `uv 0.12.17` was installed with WinGet. If a fresh terminal still cannot find `uv`,
restart the shell after installation.

## Verified starter contract

- The decision boundary is `Defense.decide(DefenseRequest) -> DefenseDecision`.
- A request contains run/step identifiers, authenticated user goal, bounded conversation and latest
  observation, candidate action, participant-visible policy context, runtime provenance, and a
  history digest. It does not contain reference plans, legitimacy labels, success conditions, or
  attacker payload fixtures.
- Outcomes are exactly `allow`, `block`, `escalate`, and `rewrite`.
- `ToolGateway` is the only existing path to a synthetic tool. It validates strict Pydantic argument
  models and rejects unknown tools.
- Official artifacts are append-only JSONL `Event` records and are rendered by `sentinel replay`.
- Published inventory: 28 scenarios (19 public, 9 validation), three domains, and 25 tools.

## Test evidence

- Main suite: `235 passed, 2 skipped` (237 collected).
- `starter-kits/python-defense`: `6 passed`.
- `starter-kits/learned-monitor`: `2 passed`.
- Ruff lint: pass.
- Ruff format check: pass after formatting.
- mypy: pass, 65 source files.
- Firewall foundation: 8 focused tests pass; Ruff and mypy pass across 69 source files.
- Firewall core: 33 focused tests pass; Ruff passes; mypy passes across 73 source files.
- Task-authority fixture unit: all 28 scenarios validate; 22 focused scenario/CLI tests pass; full
  suite `224 passed, 2 skipped`; Ruff and mypy pass.
- Live firewall unit: 44 focused tests pass. Public mock evaluation: ASR 0.0, BTU 1.0, no critical,
  data-flow, false-block, or unnecessary-escalation violations across 19 scenarios. Validation mock
  evaluation: ASR 0.0, BTU 1.0 and no task failures across 9 scenarios. These are mock-model
  diagnostics, not Qwen results.
- Skips: two symlink-escape tests on Windows error 1314 (symlink privilege unavailable). They must
  be rerun on a symlink-capable clean host before final evidence freeze.

## Security invariants for continuation

- Never pass scenario ID, path, reference plan, expected outcome, success condition, attack label,
  or evaluator legitimacy data into policy selection or a decision.
- Keep the Qwen3-8B model, system prompt, and tool set unchanged.
- Treat model assertions about authority, provenance, approval, sensitivity, policy, or trace data
  as untrusted.
- Execute only strict validated actions through a guarded executor and preserve official replay
  compatibility.
- Approval must be task/action/policy/state/version/expiry bound and consumed once.
- Rewrites are policy-owned replacements, revalidated from scratch, with no fallback.
- `Scenario.task_authorization` is runtime authority; scenario identity, attack metadata, reference
  plans, and graders remain outside every firewall decision/policy API. SENTINEL must fail closed if
  the authorization block is absent even though the general scenario parser keeps it optional for
  compatibility.

## Next safe feature unit

Run the unchanged Qwen3-8B reference model through `--defense sentinel` using the locally available
GGUF or a verified compatible local runtime. Preserve the organizer prompt and tool set. Then pin
raw evaluation metadata and build the viewer/report/video from real digest-linked traces.
