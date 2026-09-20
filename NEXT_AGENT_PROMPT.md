# Continuation prompt for the next implementation agent

You are continuing the SENTINEL IndabaX Tunisia 2026 project from the repository root on branch
`main`. Do not assume a personal absolute path; discover the checkout with `git rev-parse --show-toplevel`.

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

- Latest tested Mission Control feature commit: `9d89c52` on `origin/main`. Verify the current
  `HEAD` and `origin/main`; the final metadata commit may be one commit later.
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
- Offline viewer: `observability/sentinel-trace-viewer.html`; it now includes live follow,
  presenter playback/captions, paired trace comparison, and a multi-scorecard dashboard.
- Report/declarations/video plan: `docs/technical-report.md`, `docs/responsible-ai.md`,
  `docs/model-data-declaration.md`, `docs/video-script.md`.
- Frozen scorecards/traces and all deterministic digests: `evidence/`.

## Verified results; do not rerun just to rediscover them

- Main working-tree suite: 264 collected, `262 passed, 2 skipped`. Both skips are Windows symlink
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
- Viewer JavaScript passes `node --check`, makes no network request, and was browser-tested with a
  real rewrite trace, paired Qwen traces, and validation scorecards; no console errors were present.

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

## Exact state at this checkpoint

- The earlier fresh-clone gate was completed and recorded: `255 passed, 2 skipped`, plus starter-kit
  suites `6 passed` and `2 passed`.
- The current working-tree gate after the Mission Control/fail-closed unit is `262 passed, 2 skipped`
  of 264, with both starter-kit suites, Ruff, format, mypy, Node syntax, official replay, and public/
  validation deterministic-digest reproduction passing.
- Public and validation digests remain `b9387...` and `cb879...`; frozen scorecard outcomes were not
  rewritten. New evaluation artifacts under `artifacts/` are local verification output only.
- No known code/runtime blocker exists. The remaining submission video and upload are human-owned.

## Next tasks, in order

1. Confirm `git status`, `git log -1`, and `origin/main`. Do not overwrite user changes.
2. Do not alter frozen scorecards unless code changes invalidate them. If they do, regenerate all
   paired evidence from the same starting state and update every digest/report claim together.
3. Use `docs/video-script.md` and Mission Control to help the team record a 5-10 minute video. The recording must show a
   benign Qwen task, the Qwen attack reaching SENTINEL, the decision/reason codes, secure outcome,
   approval/lifecycle/rewrite, comparison/ablation, and an honest limitation. Label mock vs Qwen and
   replay vs adaptive execution accurately.
4. Confirm the official submission URL and deadline timezone with the organizers. Do not invent
   them. Actual upload/submission and receipt require the user's accounts and explicit involvement.

## Known limitations and intentional cuts

- Four live Qwen traces are committed, not a full-Qwen aggregate. Two benign finance/SOC tasks pass;
  two enterprise runs are secure but fail literal-date utility grading.
- One non-violating attacker-influenced draft makes public TUI 0.983; this is reported honestly.
- Risk scores are deterministic policy-severity ranks, not learned probabilities.
- Two Windows symlink tests need a symlink-capable host for full platform coverage.
- AgentDojo, Tier-2 intervention, and a server-hosted dashboard were intentionally cut under the
  project's scope-control rules; the delivered single-file Mission Control remains offline.
- Actual video recording/upload and official submission receipt are external human-account steps.

Commit each tested feature-sized unit and push to `origin/main` without force-pushing.
