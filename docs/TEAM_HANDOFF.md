# SENTINEL Team Handoff

## Current state

- Active phase: Phase 1 — contract and foundation.
- Official starter revision: `87944a1bbb4565fac853e017dac2727b0f377704`.
- Remotes: `upstream` is `Skan22/Sentinel_Starter_Kit`; `origin` is `rayen-mansouri/Indaba`.
- Mock-model baseline: verified with run ID `finance_false_approval-provenance-s0`.
- Phase exit: open. The ToolSpec/record foundation is complete; Qwen3-8B, gate evaluation, approvals,
  guarded execution, and end-to-end outcome paths remain open.

## Verified setup and commands

```powershell
uv sync
uv run pytest
uv run --project . pytest -q starter-kits/python-defense/tests
uv run --project . pytest -q starter-kits/learned-monitor/tests
uv run sentinel scenarios list scenarios --json
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml --defense provenance
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

- Main suite: `190 passed, 2 skipped`.
- `starter-kits/python-defense`: `6 passed`.
- `starter-kits/learned-monitor`: `2 passed`.
- Ruff lint: pass.
- Ruff format check: pass after formatting.
- mypy: pass, 65 source files.
- Firewall foundation: 8 focused tests pass; Ruff and mypy pass across 69 source files.
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

## Next safe feature unit

Implement trusted action normalization/provenance transformations and the deterministic G1–G7 gate
evaluator against the new records. Keep scenario/evaluator metadata structurally absent, and do not
integrate execution until focused gate tests pass.
