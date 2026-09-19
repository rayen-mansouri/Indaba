# SENTINEL — Agent Operating Protocol

This companion protocol controls how the coding work is performed. `AGENTS.md` remains the authoritative technical plan.

## Start every session this way

1. Read `AGENTS.md`, this file, `BUILD_LOG.md`, the README, current git status, and tests relevant to the active phase.
2. Identify one feature-sized unit and its exact phase exit test before editing.
3. Verify the starter-kit contract locally. Do not assume command names, scenario count, domains, supported tools, trace format, or difficulty labels from planning material.

## Keep each feature independently reviewable

- Work on one purpose at a time. Do not combine unrelated refactors, dashboard work, policy changes, and evaluation changes.
- Follow the starter-kit layout. Keep ToolSpecs/adapters, policy/gates, provenance/traces, guarded execution/approvals, viewer, tests, and documentation in distinct clear modules/directories.
- Give every feature focused tests and update the README when commands, configuration, or behavior changes.
- Make a small descriptive local git commit only after focused tests pass. Never amend unrelated commits.
- Do not push to GitHub, change remotes, open pull requests, or publish anything unless the user explicitly asks. The user will manage the repository push.

## Prevent loops and scope drift

- If an approach fails twice, stop repeating it. Record the observed failure in `BUILD_LOG.md`, inspect the actual code/contract/test evidence, choose the smallest plan-compatible alternative, and continue.
- Before changing a security invariant, policy semantic, evaluation method, or scope, record the decision, evidence, and consequence in `BUILD_LOG.md`.
- Treat unverified behavior, results, citations, and integrations as `UNVERIFIED`. Never invent them.
- Honor the delivery go/no-go checkpoints in `AGENTS.md`. Record the time, failing condition, scope cut, and next action when one triggers. Optional work must not quietly displace the security core.

## Repository and evidence hygiene

- Keep `BUILD_LOG.md` current after every feature, failed attempt, scope cut, and checkpoint.
- Record date/time, active phase, feature purpose, files changed, commands/tests and results, run/trace/configuration IDs, decisions, problem/root cause/resolution, limitations, and commit message/hash.
- Keep the repository clear for teammates: current README, precise reproduction steps, readable module boundaries, focused tests, no secrets, no personal data, no temporary model downloads, and no unnecessary generated files.
- Retain only permitted synthetic simulator evidence needed for reproducibility. Never fabricate benchmark results, coverage, external-paper claims, or successful integration.

## Completion rule

Phase status changes only when every declared exit test has actually passed and the proof is recorded in `BUILD_LOG.md`. Code existence, screenshots, or untested paths are not completion.
