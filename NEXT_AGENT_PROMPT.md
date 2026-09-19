# Continuation prompt for the next implementation agent

You are continuing the SENTINEL IndabaX Tunisia 2026 project in
`C:\Users\Mega Pc\Desktop\IndabaX2026` on branch `main`.

Work autonomously, but preserve the project's security rules and evidence integrity. Read these
files fully before changing anything:

1. `AGENTS.md`
2. `SENTINEL_BUILD_AGENT_PROTOCOL.md`
3. `BUILD_LOG.md`
4. `docs/TEAM_HANDOFF.md`
5. `docs/technical-report.md`
6. `evidence/README.md`
7. `evidence/manifest.json`
8. `AI_CONTINUATION_LOG.md`

## Mandatory logging rule

Use `AI_CONTINUATION_LOG.md` as your work journal. Before every commit, append:

- date/time and objective;
- exact files changed and why;
- exact commands/tests and their real result;
- problems, suspected/confirmed root cause, and resolution;
- remaining limitations/blockers;
- commit hash and push result.

Never erase a previous agent's entry. Never claim an unrun test, fabricated result, or incomplete
model run as success. Update `BUILD_LOG.md` and `docs/TEAM_HANDOFF.md` as required by the project
protocol as well.

## Current checkpoint

- Latest pushed commit: `b94318a` (`add reproducible evidence and submission materials`) on
  `origin/main`.
- Evidence-generating code commit: `c05a0b59d2f9b464d2099158ad123f26cc71ba3c`.
- Official starter commit: `87944a1bbb4565fac853e017dac2727b0f377704`.
- Custom defense is fully wired as `--defense sentinel`; it is not an unused library.
- G1-G7, strict ToolSpecs, immutable policy, authenticated task/workflow scope, one-time bound
  approvals, memory authority separation, field-aware provenance/sensitivity, guarded execution,
  safe rewrite revalidation, transformed-value DLP, and digest-linked trace verification are
  implemented and tested.
- `ALLOW`, `BLOCK`, `ESCALATE`, and `REWRITE` all have exercised paths.
- Live local Qwen3-8B adapter works through LM Studio without changing model, organizer system
  prompt, or tool set. Exact model/settings/hash are in `docs/model-data-declaration.md`.
- Offline viewer: `observability/sentinel-trace-viewer.html`.
- Report/declarations/video plan: `docs/technical-report.md`, `docs/responsible-ai.md`,
  `docs/model-data-declaration.md`, `docs/video-script.md`.
- Frozen scorecards/traces and all deterministic digests: `evidence/`.

## Verified results; do not rerun just to rediscover them

- Main working-tree suite: 257 collected, `255 passed, 2 skipped`. Both skips are Windows symlink
  privilege error 1314, not assertion failures.
- Starter kits: Python defense `6 passed`; learned monitor `2 passed`.
- Ruff lint and format: pass. Mypy: pass across 76 source files.
- All eight committed JSONL traces parse with official `sentinel replay`.
- All 18 committed JSON files parse; every manifest digest matches its scorecard.
- Frozen public/validation SENTINEL deterministic digests reproduced exactly:
  - public `b9387da4ac08f34064769c61c562a788937a61d4b4b7cc09f5dc3804517b0d5f`
  - validation `cb8791a524e037b9b82c47a98831e37c182e2a9ba586689af3e6111cfd224f3b`
- Full SENTINEL on public and validation: BTU 1.0, ASR 0.0, CVR 0.0, FBR 0.0, DFI 1.0,
  zero defense errors.
- Public adaptive mutation: BTU 1.0, ASR/CVR/FBR/UER 0.0, DFI 1.0.
- Validation provenance baseline fails encoded exfiltration: ASR 0.25, CVR 0.1111,
  DFI 0.8889.
- Whole-context validation ablation causes BTU 0.8 and FBR 0.0435; field-aware SENTINEL remains
  BTU 1.0.
- Viewer JavaScript passes `node --check`, makes no `fetch` call, and its initial UI was visually
  inspected in a real browser.

## Important interpretation

Do **not** implement the outside AI review's suggestion to derive authority from the natural-language
user goal. That would violate the security model. `task_authorization` is explicit out-of-band
simulator authority standing in for authenticated identity/RBAC/workflow state. The authoring
generator uses scenario IDs only to attach test input; the runtime `TaskScope`, policy selector,
`DecisionContext`, and `GateEvaluator` cannot receive scenario ID, path, labels, expected outcome,
or reference plan. This is tested and explained in the report.

The two supplied AI reviews were mostly accurate for an earlier checkpoint, but their major gaps are
now stale: wiring, rewrite, graded risk, G5 evidence, value-level decoding, Qwen invocation,
comparative results, report, and dashboard/viewer all exist. Treat the reviews as hypotheses and
verify current code before acting.

## Exact state when the previous agent stopped

- `.gitignore` was edited to add `.clean-check/` but that edit was not yet committed at the moment
  this handoff prompt was created. It should be included in this checkpoint commit.
- A fresh clone exists at `.clean-check`, checked out at `b94318a`.
- `uv sync --frozen` completed successfully inside that clone with Python 3.12.14 and 45 packages.
- The full fresh-clone pytest command was started, but the user intentionally stopped the agent
  after about 0.7 seconds. Its result is **unknown**; do not record it as pass or fail.
- No known code/runtime blocker exists.

## Next tasks, in order

1. Confirm `git status`, `git log -1`, and `origin/main`. Do not overwrite user changes.
2. Resume the clean-check only if the user has enough token budget and wants work to continue:
   run the full suite from `.clean-check`, then starter-kit tests and one SENTINEL smoke/eval. Record
   the actual result. The two symlink tests may still skip on this host.
3. If the fresh clone passes, update `AI_CONTINUATION_LOG.md`, `BUILD_LOG.md`, and
   `docs/TEAM_HANDOFF.md`; commit and push. Remove `.clean-check` only after resolving its absolute
   path inside this workspace and only if cleanup is desired.
4. Do not alter frozen scorecards unless code changes invalidate them. If they do, regenerate all
   paired evidence from the same starting state and update every digest/report claim together.
5. Use `docs/video-script.md` to help the team record a 5-10 minute video. The recording must show a
   benign Qwen task, the Qwen attack reaching SENTINEL, the decision/reason codes, secure outcome,
   approval/lifecycle/rewrite, comparison/ablation, and an honest limitation. Label mock vs Qwen and
   replay vs adaptive execution accurately.
6. Confirm the official submission URL and deadline timezone with the organizers. Do not invent
   them. Actual upload/submission and receipt require the user's accounts and explicit involvement.

## Known limitations and intentional cuts

- Four live Qwen traces are committed, not a full-Qwen aggregate. Two benign finance/SOC tasks pass;
  two enterprise runs are secure but fail literal-date utility grading.
- One non-violating attacker-influenced draft makes public TUI 0.983; this is reported honestly.
- Risk scores are deterministic policy-severity ranks, not learned probabilities.
- Two Windows symlink tests need a symlink-capable host for full platform coverage.
- AgentDojo, Tier-2 intervention, a server dashboard, and extended visual polish were intentionally
  cut under the project's scope-control rules.
- Actual video recording/upload and official submission receipt are external human-account steps.

Commit each tested feature-sized unit and push to `origin/main` without force-pushing.
