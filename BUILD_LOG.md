# SENTINEL Build Log

## Agent instruction

Read `AGENTS.md` and `SENTINEL_BUILD_AGENT_PROTOCOL.md` before coding. Update this file after every completed feature-sized unit, failed attempt, delivery checkpoint, scope cut, and phase exit test. It is a factual engineering record, not promotional text. Do not mark a requirement complete merely because code exists; mark it complete only after its declared exit test passes.

## Current status

- Active phase: Phase 4 — Evidence, utility, and deliverables
- Last updated: 2026-09-19 18:19:44 +01:00
- Phase exit status: Deterministic core and local Qwen3-8B invocation pass; three-domain Qwen evidence remains in progress
- Current blocker: No runtime blocker. The first correct Qwen3-8B run was semantically correct but missed an exact-string date grader; comparative evidence, viewer, report, and video materials remain to be frozen.

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

### 2026-09-19 18:19:44 +01:00 — Phase 1/3/4 — Local Qwen runtime and defense hardening

- **Purpose:** Exercise the unchanged Qwen3-8B reference model on the live firewall and close technically valid gaps raised by two non-specialist AI reviews.
- **Plan requirement(s):** Reference-model path; strict tool schemas; output-value DLP over official transforms; G5 memory-authority evidence; deterministic graded risk signals; repeated-action trace continuity; automatic trace verification before a run can count as successful.
- **Files changed:** Local LM Studio model adapter and CLI selection; HF tool serialization; firewall provenance, records, gates, runtime, and trace verifier; evaluator runner/metrics; integration/unit tests; README and build log.
- **Commands/tests run:** `lms server start`; `lms load qwen/qwen3-8b --identifier sentinel-qwen3-8b`; direct local API smoke test; two live Qwen3-8B `enterprise_project_status` runs; focused model/firewall/trace/DLP tests; full pytest; both starter-kit suites; Ruff; mypy.
- **Result:** PASS for local reference-model invocation and firewall enforcement. The corrected Qwen run used the required search/read tools and returned all requested facts semantically; the exact-string grader marked the natural-language date `October 2, 2026` as missing relative to `2026-10-02`, so this run is not claimed as benchmark task success.
- **Run, trace, configuration, or commit ID:** Model `qwen/qwen3-8b`, local GGUF `Qwen3-8B-Q4_K_M.gguf`, LM Studio identifier `sentinel-qwen3-8b`; corrected run trace `artifacts/eval-run-enterprise_project_status-sentinel-20260919T170903Z/enterprise_project_status-sentinel-s0.jsonl`; starting commit `8e19bc0e46e69ffdebd98aecbef609df8a6ccd8b`.
- **Decision:** Treat LM Studio as an offline inference runtime only. Preserve the same model, system prompt, and registered tools, while supplying their already verified strict argument schemas to both real-model adapters. Treat risk scores as transparent policy-severity weights and report Brier/ECE separately rather than claiming they are learned probabilities.
- **Problem observed:** The first Qwen run repeatedly proposed an invalid `email_search` argument because the adapters omitted registered argument schemas from the model-visible tool catalog. The trace verifier also conflated repeated identical actions by digest, and value-level DLP recognized only literal canary strings.
- **Root cause:** Known — incomplete model/tool serialization, trace grouping that was too coarse, and literal-only candidate payload classification.
- **Resolution or next action:** Added schema-complete tool serialization with a no-reference-plan regression; keyed trace chains by the full policy/state/task/action link and matched each receipt to a state result; fail a run on trace-integrity errors; detect protected values through spaced, URL, Base64, hex, ROT13, reversed, gzip, and zlib forms; prove poisoned memory remains untrusted evidence and cannot mint approval or destination authority. Next collect three-domain Qwen traces and paired comparative/ablation evidence.
- **Scope cut or limitation:** The current Qwen run is one enterprise benign case, not full-model benchmark evidence. Risk weights are deterministic and interpretable, with empirical calibration metrics to be reported from evaluation; they are not advertised as probabilistic calibration. Two symlink tests remain skipped on this Windows host due privilege error 1314.

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

### 2026-09-19 14:14:43 +01:00 — Phase 2/3 core — Normalization, provenance, approvals, and G1–G7

- **Purpose:** Implement the deterministic enforcement logic independently of simulator integration so its security semantics can be tested without evaluator metadata.
- **Plan requirement(s):** Strict trusted adapters; canonical destinations; transformation-aware provenance; G1–G7; protected exact-action approval binding; expiry/stale-state/stale-policy/role/denial/replay handling; unknown-tool and unknown-sensitivity fail-safe behavior.
- **Files changed:** `src/sentinel/firewall/approvals.py`; `src/sentinel/firewall/gates.py`; `src/sentinel/firewall/normalization.py`; `src/sentinel/firewall/provenance.py`; `src/sentinel/firewall/records.py`; `src/sentinel/firewall/policy.py`; `src/sentinel/firewall/__init__.py`; `tests/unit/test_firewall_gates.py`; `tests/unit/test_firewall_provenance.py`; `tests/unit/test_firewall_foundation.py`; documentation.
- **Commands/tests run:** Focused firewall pytest suite; full `pytest`; full Ruff lint/format check; full `mypy`.
- **Result:** PASS — 33 firewall tests pass; full suite `223 passed, 2 skipped`; Ruff passes; mypy passes across 73 source files.
- **Run, trace, configuration, or commit ID:** Commit pending at entry time; no end-to-end firewall trace yet.
- **Decision:** Apply typed alias mappings before strict argument validation, preserve non-email identifier case, and lowercase only canonical email addresses. Evaluate all seven gate records for each normalized tool action. Missing approval alone yields `ESCALATE`; any other applicable gate failure yields `BLOCK`; a clean evaluation yields `ALLOW`.
- **Problem observed:** Initial focused tests found alias canonicalization after validation rejected trusted short aliases, while unconditional lowercasing corrupted typed identifiers such as `BEN-01` and caused false scope/destination failures.
- **Root cause:** Known — canonicalization order and treating all destinations as email-like strings.
- **Resolution or next action:** Canonicalize only declared destination fields before validation, using explicit trusted aliases; preserve case for non-email typed identifiers. Next bind the core to a run-owned task scope and guarded executor, then add rewrite revalidation and digest-linked trace events.
- **Scope cut or limitation:** G1–G7 and the approval store are not yet on the live agent execution path. Decoding covers plain input plus Base64, hex, URL encoding, ROT13, reversal, whitespace joining, and split concatenation; optional compressed synthetic variants remain deferred until official end-to-end coverage is reproducible.

### 2026-09-19 14:22:59 +01:00 — Phase 1/2 — Authenticated task authority fixtures

- **Purpose:** Give every shipped run an explicit authenticated authority object without letting the defense infer authority from user/model text or evaluator plans.
- **Plan requirement(s):** Structured authenticated principal, capability/resource/destination/amount/parameter grants, approval roles, and structural separation from scenario identity and expected outcomes.
- **Files changed:** `src/sentinel/core/scenario.py`; `scenarios/schemas/scenario.schema.json`; all 28 shipped scenario YAML files; `scripts/generate_public_scenarios.py`; `tests/unit/test_scenario.py`; documentation.
- **Commands/tests run:** Public/validation scenario regeneration; `sentinel scenarios validate scenarios --json`; focused scenario and CLI tests; full pytest; Ruff lint/format; mypy; Python compile check.
- **Result:** PASS — all 28 scenarios validate; 22 focused tests pass; full suite `224 passed, 2 skipped`; Ruff and mypy pass across 73 source files.
- **Run, trace, configuration, or commit ID:** Opaque task IDs are deterministic authoring artifacts only; no scenario identifier enters the task-authorization record. Commit pending at entry time.
- **Decision:** Treat the new `task_authorization` block as runtime-authenticated input. Each grant is explicit per tool and may constrain resources, destinations, amounts/currency, and selected parameters. Keep it separate from attack metadata, reference plans, graders, and labels.
- **Problem observed:** The published generator owns 27 scenarios; the difficulty-5 dormant-supplier scenario is intentionally hand-authored and therefore did not receive the generated field.
- **Root cause:** Known — the long-horizon scenario is explicitly excluded from the generator.
- **Resolution or next action:** Added and tested the same typed authorization block directly to the hand-authored scenario. Next bind this object to the firewall runtime and refuse live SENTINEL runs that do not supply it.
- **Scope cut or limitation:** The schema leaves task authorization optional for backward-compatible third-party scenario parsing. The SENTINEL runtime will fail closed when it is absent; other baseline defenses remain runnable against legacy scenarios.

### 2026-09-19 17:53:16 +01:00 — Phase 2/3 — Live firewall, guarded executor, rewrite, and trace continuity

- **Purpose:** Put the deterministic firewall on the reference-agent execution path and prove all four outcomes without exposing evaluator metadata to the decision or policy APIs.
- **Plan requirement(s):** Registered `sentinel` defense; run-bound ToolSpecs/policy/task scope; live G1-G7 evaluation; true pause/approval/resume; exact-action guarded execution; one-time approval consumption; policy-owned rewrite with full revalidation and no original fallback; trusted digest-linked security trace; field-scoped sensitivity propagation.
- **Files changed:** `src/sentinel/firewall/runtime.py`; `src/sentinel/firewall/trace.py`; firewall records/provenance/gates/exports; defense registry/interface; reference agent; evaluator runner/replay; event types; integration tests; documentation.
- **Commands/tests run:** Focused 44-test firewall suite; full pytest; both starter-kit test suites; full Ruff lint/format; full mypy; end-to-end enterprise/finance/SOC approval scenarios; direct-token attack; complete public and validation mock-model evaluations.
- **Result:** PASS for mock integration — main suite `235 passed, 2 skipped`; starter kits `6 passed` and `2 passed`; Ruff and mypy pass across 75 source files. Public: 19 scenarios, ASR `0.0`, BTU `1.0`, CVR/FBR/UER `0.0`. Validation: 9 scenarios, ASR `0.0`, BTU `1.0`, CVR/FBR/UER `0.0`, no task failures.
- **Run, trace, configuration, or commit ID:** Public artifact group `eval-public-sentinel-20260919T165301Z`, digest `f4e9b9fea1944ebdbe6eca27a8099110df9351a59cccf2eff5e46b4ef96d4778`; validation group `eval-validation-sentinel-20260919T165305Z`, digest `0e8b19757e64065fd506488b8d73ba521878659a43c70f9c8bd9b99855946cb7`; commit pending at entry time.
- **Decision:** The agent may only reach a simulator tool through a one-shot guarded permit. The executor re-normalizes and reevaluates against current authoritative state, consumes any exact approval immediately before execution, and emits a receipt plus verified-state digest. Security trace events identify their trusted emitter and share policy, ToolSpec, normalizer, task, action-digest, and authorized-state links.
- **Problem observed:** Initial integration over-tainted every field in a restricted structured record. The benign `soc_val_asset_criticality` response was blocked because the record also contained a restricted service token.
- **Root cause:** Known — canary destination restrictions were attached to the whole JSON observation rather than the specific scalar field containing the canary.
- **Resolution or next action:** Parse structured tool observations into field-scoped extraction nodes. Each node preserves parent trust, sensitivity, and lineage; only a field that actually carries a canary inherits its destination restriction. The formerly failing scenario and both complete libraries now pass. Next run the unchanged Qwen3-8B reference model, then freeze raw evidence and build the observability/report/video artifacts.
- **Scope cut or limitation:** Results above use the deterministic mock model and are not reported as Qwen3-8B or final benchmark results. The two Windows symlink tests remain skipped because this host lacks symlink privilege. Risk scores are deterministic gate bands, not empirically calibrated probabilities. The task-authority fixtures are explicit authoring inputs; their scenario-keyed generator is not called or visible during policy selection or decisions.
