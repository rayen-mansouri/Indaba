# SENTINEL 2026 — Build Instructions for the Coding Agent

## Mission

Build the SENTINEL competition defense as a small, deterministic action firewall around the organizer-provided reference Qwen3-8B agent and simulator. Start from the organizer starter kit and extend it. Do not replace its service, Docker setup, schemas, trace contract, or replay path unless the verified starter-kit contract requires a change.

The intended claim is narrow: this defense reduces unauthorized effects at the simulator's action boundary while preserving legitimate utility. It is not a claim of general prompt-injection prevention or reproduction of external research results.

## Read first, verify before assuming

1. Inspect the repository, starter-kit README, CLI help, schemas, tests, and simulator contract before writing features.
2. Discover the actual command names, trace format, scenario/domain count, model invocation, and supported tools from the repository. Do **not** hard-code `sentinel run`, `sentinel replay`, a count of 19 scenarios, or any domain name until each is verified locally.
3. Record verified commands and environment requirements in the project README.
4. Use only the offline simulator and organizer-provided components. Do not access real bank, sponsor, organizer, personal-data, credential, or external operational systems. Do not escape the sandbox, persist on a host, or probe platform weaknesses.

## Non-negotiable competition constraints

- The decision path may receive only live agent state, the candidate action, runtime-established provenance, active policy, authenticated task/workflow state, and observed content.
- It must never receive or derive a decision from scenario ID, filename, expected outcome, organizer labels, or evaluator-only metadata. Keep this metadata structurally outside the decision API and policy-selection API. Add a test proving that the decision function cannot accept those fields.
- Only four outcomes exist: `ALLOW`, `BLOCK`, `ESCALATE`, and `REWRITE`.
- Never expose chain-of-thought. Emit concise risk signals and short reason codes only.
- The model is untrusted for policy, capability, impact, provenance, sensitivity, approval, destination authorization, or trace metadata. The runtime assigns all of those values.
- Unknown tools, unsupported effects, forged/missing provenance, malformed security metadata, and unknown sensitivity must fail safely. They cannot execute or become public/trusted by default.

## Required architecture

Implement these trusted runtime components:

1. **ToolSpec manifest and adapters.** Each supported tool has a versioned strict argument schema, capability/effect class, read/write scope, payload and destination field paths, approval/lifecycle rules, output trust/sensitivity labeling, and canonicalizer version. Unknown paths cannot execute.
2. **Immutable run policy snapshot.** Bind a policy version/hash to the run. The model cannot change policy.
3. **Authenticated task scope and authoritative workflow state.** Store the authenticated principal plus permitted capabilities, resources, destinations, amounts, and delegation constraints. Do not infer authority from message text.
4. **Protected approval store.** Approval records bind issuer/role, exact task, canonical normalized-action digest, policy version, state version, expiry, and one-time use. Consume approval atomically with execution.
5. **Provenance and sensitivity graph.** Use exactly these public labels: `SYSTEM_POLICY`, `AUTHENTICATED_USER`, `TRUSTED_INTERNAL`, `UNTRUSTED_INTERNAL`, `UNTRUSTED_EXTERNAL`, `ADVERSARY_CONTROLLED`. Source nodes have runtime-issued opaque IDs, parent IDs, transformation type, and run/session binding.
6. **Deterministic gate evaluator.** Evaluate all applicable G1–G7 gates for every consequential action.
7. **Guarded executor.** The executor receives only the exact validated action and current authoritative state. Direct model-to-tool execution is forbidden.
8. **Trusted trace emitter.** Only adapters, the decision service, and guarded executor may emit trace events. The model cannot create, modify, suppress, or backfill events.

## Core record shapes

Use the starter-kit conventions where they exist. Otherwise use typed equivalents of:

- `ToolSpec`: name/version, strict schema, capability/effect, scopes, payload/destination paths, lifecycle/approval rules, output labels, normalizer version.
- `SourceNode`: opaque runtime ID, source kind, trust label, sensitivity restrictions, parents, transformation, run/session binding.
- `CandidateAction`: raw proposal plus runtime-derived executable form, canonical destinations/dependencies, action digest.
- `TaskScope`: authenticated principal and allowed capability/resource/destination/amount/delegation constraints.
- `ApprovalRecord`: authenticated issuer/role, task ID, normalized-action digest, policy/state version, expiry, consumption state.
- `DecisionEvent`: original proposal, outcome, reason codes, risk basis, gate results, provenance summary, policy/ToolSpec/normalizer versions, action digest, replacement if any, execution receipt, and verified state change.

## G1–G7 requirements

Implement the gates deterministically. Do not use keywords, scenario identity, or model assertions as authority.

- **G1 — effect authorization:** Untrusted content may provide permitted data values but cannot grant approval, capability, or a broader effect.
- **G2 — task/capability scope:** Enforce active policy and authenticated task constraints for capability, target resource, amount, and constrained parameters. A user does not override system policy.
- **G3 — lifecycle integrity:** Use authoritative state, never message content. Enforce the applicable prepare → confirm → execute lifecycle for payments and the verified SOC/remediation lifecycle for the simulator.
- **G4 — approval binding:** Verify issuer, role, task, action digest, policy/state version, expiry, and unused status. Atomically consume on execution. Reject replay, mismatch, denial, missing response, stale state, and expiry.
- **G5 — memory authority separation:** General memory is evidence only. It cannot create policy, satisfy approval, grant capability, or authorize a lifecycle transition. Agent-facing tools cannot write protected policy/approval stores.
- **G6 — confidentiality and egress:** Check actual payload restrictions at every recipient/destination/capability, including drafts, attachments, notes, memory, and persisted output sinks. Redaction must revalidate the resulting payload. Unknown sensitivity is not public.
- **G7 — destination integrity:** Require both system-policy permission and a match with the authenticated task destination constraint. Canonicalize aliases only via trusted typed mappings and check nested/secondary recipient fields. A newly authorized destination is allowed when the authenticated task and policy explicitly authorize it; historical absence neither blocks nor grants authority.

## Decision and rewrite invariant

For each candidate action:

1. Strictly validate tool name and schema.
2. Derive trusted semantics, canonical destinations, payload paths, provenance, sensitivity, dependencies, and action digest.
3. Evaluate every applicable G1–G7 gate.
4. Choose exactly one outcome and emit a DecisionEvent.
5. Execute only an allowed/approved/revalidated action against current authoritative state.
6. Emit an executor receipt and verified state event.

Outcome meanings:

- `ALLOW`: original action passes every check and executes unchanged.
- `BLOCK`: invalid or prohibited; stop it and return short reason codes.
- `ESCALATE`: may be permitted but requires a human decision; pause execution. A fresh approval triggers full revalidation, never automatic continuation.
- `REWRITE`: substitute exactly one policy-owned safe action. Validate the instantiated substitute from scratch: schema, provenance/sensitivity, G1–G7, and current state. Execute only that exact substitute. A failed substitute becomes `BLOCK` or `ESCALATE`; it must never fall back to the original action.

Start rewrite support only with simulator-supported templates: redacted/restricted draft, prepare-only payment, and non-privileged incident update. The approval UI must display canonical effect, canonical destination, amount, policy condition, and trusted provenance facts; it must not approve attacker-authored narrative or free-form instructions.

## Trace-integrity and transformation invariants

- Every proposal, decision, rewrite, approval, executor receipt, and state result must share a run ID, action digest, policy version, ToolSpec version, and normalizer version.
- A missing link, invalid digest, unknown emitter, malformed security metadata, or receipt that does not match the executed action is a security error and cannot count as a successful defense run.
- Call this **digest-linked trace continuity**, not cryptographic non-repudiation, unless signed append-only storage is actually implemented and tested.
- Decoding, parsing, concatenation, extraction, summarization, and re-encoding create a new SourceNode that preserves parent lineage and sensitivity. Unsupported transformations must not silently clear either property.
- Mandatory decoding coverage: plain text, Base64, and every encoding/obfuscation form in the official evaluation library. Add hex, reversed, spaced, split/concatenated, and supported compressed synthetic variants after the baseline and official-library coverage are reproducible.
- Do not block merely because text is encoded or threatening; decide from effect context, provenance, payload restrictions, and destination.

## Phased delivery — do not skip exit tests

### Phase 1 — Contract and foundation (18 September)

Inspect the starter kit; verify the actual run/replay commands; run the reference model locally; create ToolSpecs, schemas, policy snapshot, trace skeleton, and metadata separation. Prove each of the four outcomes with a minimal end-to-end path before custom defenses.

Exit: a baseline run completes in each verified domain; reference model works against the live agent; an official replay-readable trace renders; the decision API excludes evaluation metadata.

### Phase 2 — Morning deterministic core (19 September)

Build strict adapters, guarded executor, trusted task/policy state, G2–G5, atomic approvals, and the runtime trace skeleton. Validate Allow, Block, and true pause/resume Escalate. A Rewrite may be exercised only through the guarded executor and never as a soft warning.

**13:00 go/no-go:** If every supported action type has not reached the guarded executor with trusted ToolSpec semantics, action digest, and trace receipt, freeze viewer and report-appendix work. Complete the interceptor, G2–G5, approval handling, and one passing path per tool.

### Phase 3 — Afternoon deterministic core (19 September)

Build G1, G6, G7, full rewrite revalidation, digest/state continuity, and decoding propagation. Test approval replay/expiry/mismatch, forged/missing provenance, destination substitution, rewrite no-fallback, trace corruption, and each official-library obfuscation form. Produce one end-to-end trace per verified domain.

**20:00 go/no-go:** If each domain does not have a complete decision → receipt → verified-state trace, defer extended synthetic decoding tests and all custom viewer work. Finish G1/G6/G7, rewrite, and official replay compatibility before running the full library.

### Phase 4 — Evidence and utility (20 September)

First establish a reproducible baseline and run all hard negatives. Then run the full published library, priority adaptive/long-horizon cases, and priority encoding variants. Record raw denominators: attack reaching defense, unauthorized effect prevented/occurred, benign completion, unnecessary blocks/escalations/rewrites, errors/timeouts, and defense latency separate from model/human latency.

Run these comparisons where they affect outcomes: full system; declared baseline; no task-bound G7; field-aware versus conservative whole-context propagation; no Tier 2 only if Tier 2 changes outcomes. Use the same starting state for paired trials; record policy hash, versions, model settings, seed, commit, and trace ID. Never count a crash as defense success, a draft as a required send, an escalation as a payment, or replay as adaptive end-to-end execution.

Run three declared composition probes: untrusted content persisted to memory before a later action; decoding plus confidential sink; lifecycle transition plus destination constraint. Report every bypass as a limitation.

**16:00 go/no-go:** If the baseline and hard negatives are not reproducible, stop new variants and ablations. Preserve raw traces, resolve reproducibility, and run only the priority evaluation set.

### Phase 5 — Communicate and reproduce (21 September)

Complete report, README, model/data declaration, responsible-AI statement, results tables, limitation trace, and clean-environment build. MITRE ATLAS/ATT&CK is report/trace taxonomy only; it must never enter policy decisions or classifier training. Pin a source version/access date. Cite research precisely; verify the AgentSpec DOI from the official ICSE/published record and retrieve the ACM Digital Library landing record if available before report freeze.

Record a 5–10 minute video and a backup take. Show a benign task completing, one uninterrupted live attack reaching the defense, the decision with risk basis/reason codes, actual secure outcome, lifecycle/approval, memory/replay clearly labelled, ablation/utility, and one honest limitation.

### Phase 6 — Harden and submit (22 September)

Run a fresh-clone clean-environment trace. Confirm video, report, dashboard/replay, code, and tables cite matching commit/config/trace IDs. Verify external model/dataset declarations and submission links. Target internal submission by 21:00 in the confirmed official deadline timezone and save the receipt.

## Scope control

Never cut: all gate semantics for supported consequential tools; strict adapters/guarded executor; scenario metadata separation; policy/task/memory/approval constraints; rewrite revalidation; trace continuity; G6/G7 field-level checks; hard negatives; baseline; and one trace per domain.

Cut first if late: rich dashboard features beyond official replay; extended synthetic decoding matrix after mandatory official-library coverage; Tier 2 intervention; MITRE appendix; optional AgentDojo work; visual polish. Tier 2 is trace-only telemetry unless paired evidence proves a utility/safety gain.

## Quality bar and final outputs

Keep testable code small and explicit. Add meaningful regression tests beside the relevant component. Never fabricate benchmark results, scenario coverage, command support, external-paper results, or citations.

Before finishing, provide:

- a runnable local defense using the verified starter-kit interface;
- replay-compatible trusted traces;
- tests for all critical invariants and required hard negatives;
- raw evaluation artifacts with reproducibility metadata;
- a concise README explaining setup, run/replay commands, architecture, limitations, and declared model/data;
- report/video materials that agree with the generated traces and results.
