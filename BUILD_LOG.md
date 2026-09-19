# SENTINEL Build Log

## Agent instruction

Read `AGENTS.md` and `SENTINEL_BUILD_AGENT_PROTOCOL.md` before coding. Update this file after every completed feature-sized unit, failed attempt, delivery checkpoint, scope cut, and phase exit test. It is a factual engineering record, not promotional text. Do not mark a requirement complete merely because code exists; mark it complete only after its declared exit test passes.

## Current status

- Active phase: Phase 1 — Contract and foundation
- Last updated: 2026-09-19 13:58:05 +01:00
- Phase exit status: In progress
- Current blocker: The mock-model contract is verified; the reference Qwen3-8B run and custom deterministic foundation are not yet complete.

## Entry template

### YYYY-MM-DD HH:MM — Phase N — Feature name

- **Purpose:**
- **Plan requirement(s):**
- **Files changed:**
- **Commands/tests run:**
- **Result:** PASS / FAIL / PARTIAL / UNVERIFIED
- **Run, trace, configuration, or commit ID:**
- **Decision:**
- **Problem observed:**
- **Root cause:** Known / suspected / unknown
- **Resolution or next action:**
- **Scope cut or limitation:** None / describe

## Entries

### 2026-09-18 22:02:36 +01:00 — Phase 1 — Starter-kit contract audit

- **Purpose:** Verify the organizer starter-kit contract before implementing any foundation code.
- **Plan requirement(s):** Inspect README, CLI help, schemas, tests, Docker setup, simulator interface, reference Qwen3-8B invocation, supported tools/domains/scenarios, and official trace/replay path; record verified commands locally.
- **Files changed:** `BUILD_LOG.md`
- **Commands/tests run:** `Get-Location`; `git status --short --branch`; `Get-ChildItem -Force`; recursive `Get-ChildItem -Force -Recurse`; `Get-Command git`; attempted `rg --files`; attempted read of `README.md`.
- **Result:** BLOCKED
- **Run, trace, configuration, or commit ID:** None; no git repository or runnable starter kit is present.
- **Decision:** Do not invent simulator commands, domains, scenarios, tools, schemas, model invocation, trace format, replay behavior, tests, or Phase 1 implementation.
- **Problem observed:** The workspace contains only `AGENTS.md`, `BUILD_LOG.md`, and `SENTINEL_BUILD_AGENT_PROTOCOL.md`. `README.md` is missing; no source, tests, Docker files, schemas, simulator, reference model, trace/replay path, or git metadata were found. `rg` is not installed. The log previously referenced `BUILD_AGENT_PROTOCOL.md`, which does not exist.
- **Root cause:** Known - the organizer starter kit has not been supplied in this workspace.
- **Resolution or next action:** Supply or open the starter-kit repository in this workspace, including its README, executable/package metadata, CLI, schemas, tests, Docker setup, simulator, reference-model integration, and trace/replay implementation. Then rerun the contract audit before selecting the first implementation unit.
- **Scope cut or limitation:** Phase 1 implementation is deferred. No setup/run/replay command, domain count, scenario count, supported tool, trace format, baseline result, or exit test can be verified locally.

### 2026-09-19 12:54:17 +01:00 — Phase 1 — Starter-kit contract audit rerun

- **Purpose:** Rerun the starter-kit contract audit after the previous blocker report.
- **Plan requirement(s):** Verify actual README, CLI/help, schemas, tests, Docker setup, simulator interface, reference Qwen3-8B invocation, supported tools/domains/scenarios, trace format, official replay path, and baseline results before custom defenses.
- **Files changed:** `BUILD_LOG.md`
- **Commands/tests run:** `Get-Location`; `git status --short --branch`; recursive `Get-ChildItem -Force -Recurse`; filtered artifact search for README/Docker/package/project/test/schema/trace/replay/simulator/Qwen/CLI files; `Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'`.
- **Result:** BLOCKED
- **Run, trace, configuration, or commit ID:** None; no starter-kit executable, test run, trace, baseline run, or git commit exists locally.
- **Decision:** Contract audit does not pass. Do not implement ToolSpecs, schemas, policy snapshots, traces, decision API, outcome paths, or custom defenses until the starter kit is present and its contract is verified.
- **Problem observed:** The recursive inventory still contains only `AGENTS.md`, `BUILD_LOG.md`, and `SENTINEL_BUILD_AGENT_PROTOCOL.md`. No README, CLI, package/project metadata, schemas, tests, Docker setup, simulator, reference model, supported-tool manifest, domain/scenario data, trace format, replay path, or baseline fixture/result is available. `git status` fails because this directory is not a git repository.
- **Root cause:** Known - the organizer starter kit and its contract artifacts are still absent from the workspace.
- **Resolution or next action:** Supply or open the complete organizer starter-kit repository in this workspace. Then verify its README, CLI help, supported tools/domains/scenarios, schemas, simulator/model path, trace/replay path, and baseline run before selecting a Phase 1 implementation unit.
- **Scope cut or limitation:** No verified command, tool, schema, trace format, domain count, scenario count, reference-model result, replay result, or baseline result exists. Phase 1 remains not started; no implementation or commit was made.

### 2026-09-19 13:50:50 +01:00 — Phase 1 — Starter-kit contract audit and Windows portability

- **Purpose:** Replace the stale missing-kit blocker with a locally verified starter-kit contract and make its security suite produce meaningful results on Windows.
- **Plan requirement(s):** Pull and record the official starter revision; inspect README, CLI help, schemas, tools, policies, scenarios, decision API, runner, gateway, trace, and replay path; run setup, tests, and the official baseline before custom defense work.
- **Files changed:** `.gitignore`; `src/sentinel/core/scenario.py`; `tests/security/test_input_safety.py`; `tests/unit/test_submission.py`; `README.md`; `docs/TEAM_HANDOFF.md`; `BUILD_LOG.md`.
- **Commands/tests run:** `git fetch --prune upstream`; `git fetch --prune origin`; `uv sync --cache-dir .uv-cache`; `sentinel --help`; `sentinel run --help`; `sentinel replay --help`; `sentinel eval --help`; `sentinel scenarios list scenarios --json`; `sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml --defense provenance`; `pytest`; both starter-kit pytest suites; focused input-safety/state/submission tests; `ruff check`; `ruff format --check`; `mypy`.
- **Result:** PARTIAL — setup, mock baseline, trace, replay contract, lint, typing, and tests pass; the Phase 1 reference-model and custom-foundation exits remain open.
- **Run, trace, configuration, or commit ID:** Official starter commit `87944a1bbb4565fac853e017dac2727b0f377704`; baseline run `finance_false_approval-provenance-s0`; trace `artifacts/eval-run-finance_false_approval-provenance-20260919T124503Z/finance_false_approval-provenance-s0.jsonl`; commit pending at entry time.
- **Decision:** Keep the organizer CLI, runner, HTTP schema, model prompt, tools, gateway, JSONL event model, and replay path. Extend through isolated defense/runtime modules. Do not use the evaluator's scenario ID, reference plan, labels, success conditions, or expected outcomes in a decision.
- **Problem observed:** `uv` and GNU Make were absent. The first sandboxed test run could not use the user temp directory. The unrestricted Windows run exposed one real portability defect (`/etc/passwd.json` passed `Path.is_absolute()` on Windows) and two tests that assumed symlink privileges.
- **Root cause:** Known — host setup plus platform-specific path and symlink behavior, not defense behavior.
- **Resolution or next action:** Installed `uv 0.12.17`; executed Makefile targets directly because GNU Make is unavailable; made fixture absolute-path validation portable across POSIX and Windows syntax; skip symlink assertions only when Windows reports privilege error 1314. Final results: main suite `190 passed, 2 skipped`; python-defense kit `6 passed`; learned-monitor kit `2 passed`; Ruff passed; mypy passed. Next implement the typed ToolSpec/policy/task-scope foundation without evaluation metadata.
- **Scope cut or limitation:** The two skipped tests still need a symlink-capable clean-environment run. `make test` and `make run-baseline` were executed via their exact underlying commands because this host lacks GNU Make. Qwen3-8B has not yet been exercised through the reference adapter.

### 2026-09-19 13:58:05 +01:00 — Phase 1 — Trusted ToolSpec and decision-record foundation

- **Purpose:** Establish immutable trusted types for later G1–G7 evaluation without changing the organizer model, tools, HTTP contract, gateway, or replay path.
- **Plan requirement(s):** Strict versioned ToolSpecs for every supported tool; immutable policy snapshot; authenticated task scope; authoritative workflow-state shape; runtime provenance/source-node shape; candidate normalization record; structural exclusion of evaluator-only metadata.
- **Files changed:** `src/sentinel/firewall/__init__.py`; `src/sentinel/firewall/records.py`; `src/sentinel/firewall/toolspecs.py`; `src/sentinel/firewall/policy.py`; `tests/unit/test_firewall_foundation.py`; `README.md`; `docs/TEAM_HANDOFF.md`; `BUILD_LOG.md`.
- **Commands/tests run:** `pytest -q tests/unit/test_firewall_foundation.py`; `ruff check src/sentinel/firewall tests/unit/test_firewall_foundation.py`; `ruff format --check src/sentinel/firewall tests/unit/test_firewall_foundation.py`; `mypy`.
- **Result:** PASS — 8 focused tests pass; Ruff passes; mypy passes across 69 source files.
- **Run, trace, configuration, or commit ID:** ToolSpec version `1.0.0`; normalizer version `sentinel-c14n/1`; commit pending at entry time.
- **Decision:** Keep schemas derived from the actual runtime tool argument models, but require an explicit trusted semantics overlay for every registered tool. Manifest construction fails if a tool is unknown or an overlay is stale. Store strict schema as canonical JSON so the frozen record has no mutable nested schema object.
- **Problem observed:** Pydantic frozen models do not make nested dictionaries deeply immutable; an ordinary schema dictionary would therefore weaken the immutable-manifest claim.
- **Root cause:** Known — Python container mutability inside otherwise frozen models.
- **Resolution or next action:** Store canonical schema and policy bodies as strings, expose parsed copies, and bind each snapshot to a deterministic SHA-256. Next add trusted action normalization/provenance transformation and the deterministic G1–G7 evaluator.
- **Scope cut or limitation:** This unit defines trusted records and coverage only. It does not yet bind a scope to a scenario run, issue approvals, evaluate gates, or execute actions.
