# Changes made on top of the organizer starter

The team started from organizer commit
`c86681a74f3bd7cf1c6be7b3251b575c8600f910`. SENTINEL is an in-process defense integrated with the
organizer runner; it is not presented as an untouched drop-in HTTP starter.

Organizer contracts intentionally preserved:

- Qwen3-8B identity, current organizer system prompt, tool catalog, and strict argument schemas;
- scenario, fixture, policy, event, JSONL trace, replay, and Docker/starter-kit formats;
- the four decision outcomes and the existing simulator gateway;
- fully offline synthetic tools and evaluator-owned grading.

Integration changes:

- added the `src/sentinel/firewall/` trusted runtime and registered `--defense sentinel`;
- extended scenario schema/fixtures with protected synthetic task-authorization envelopes;
- bound SENTINEL to policy, task scope, live workflow state, ToolSpecs, guarded execution, and the
  trusted event log before an agent run;
- routed allowed, approved, and rewritten SENTINEL actions through one-shot guarded permits;
- added firewall/approval/rewrite/receipt/state events while retaining official JSONL and replay;
- added the local LM Studio adapter, offline viewer, regression tests, evidence, and report assets;
- updated both real-model adapters to the current organizer prompt/tool-card behavior from
  `c86681a`.

Evaluator-only scenario IDs, attack labels, reference plans, success conditions, expected outcomes,
and canary registries do not enter the firewall decision API. The evaluator still uses those values
after execution to score runs.
