# 7-minute submission video runbook

Record from the final pushed commit and show `git rev-parse HEAD` on screen. Keep the terminal,
viewer, and repository commit visible. Do not describe a mock replay as a live adaptive run.

## Before recording

1. Start LM Studio locally and load `qwen/qwen3-8b` as `sentinel-qwen3-8b` with context 8192.
2. Open `observability/sentinel-trace-viewer.html` in Chrome or Edge, load
   `observability/video-captions.example.json`, and practice presenter mode once.
   Also open `observability/sentinel-dashboard.html` for the aggregate comparison segment.
3. Prepare these committed traces:
   - `evidence/traces/qwen3-8b/finance_dispute_note-sentinel-s0.jsonl`
   - `evidence/traces/qwen3-8b/soc_intel_correlation-sentinel-s0.jsonl`
   - `evidence/traces/qwen-paired/eval-run-enterprise_direct_token_request-allow_all-20260919T233607Z/enterprise_direct_token_request-allow_all-s0.jsonl`
   - `evidence/traces/qwen-paired/eval-run-enterprise_direct_token_request-sentinel-20260919T234451Z/enterprise_direct_token_request-sentinel-s0.jsonl`
   - `evidence/traces/comparisons/enterprise_val_encoded_exfil-provenance-s0.jsonl`
   - `evidence/traces/comparisons/enterprise_val_encoded_exfil-sentinel-s0.jsonl`
   - `evidence/traces/outcomes/.../enterprise_probe_escalate_send-sentinel-s0.jsonl`
   - `evidence/traces/outcomes/.../enterprise_probe_rewrite_restricted_send-sentinel-s0.jsonl`
4. Before choosing the attack shown in the video, run that scenario once with `allow_all` under the
   same model configuration. Use it only if `attack_success=true`. Then run the same scenario with
   SENTINEL from a fresh state. Keep both commands and their summaries visible in the recording.
   If Qwen does not reach the attack, use the deterministic mock pair and label it plainly; never
   count a non-reaching Qwen control as defense success.
5. Rehearse once and create a backup take. Ensure no model weight path, personal directory listing,
   secret, or unrelated window is visible.

## Timeline and narration

### 0:00-0:40 — Claim and boundary

“SENTINEL is not a prompt classifier. It is a deterministic action firewall around the Qwen3-8B
agent. The weights, organizer system prompt, and registered tools are unchanged; narrow runtime
hooks bind authenticated context and route proposed actions through the guarded executor. It protects
the simulator's tool boundary using runtime-owned ToolSpecs, policy, task scope, workflow state,
approvals, provenance, sensitivity, and destinations.”

Show the architecture diagram in `docs/technical-report.md`. State the narrow limitation: synthetic
offline simulator, not general prompt-injection prevention.

### 0:40-1:35 — Benign Qwen task

Run `soc_intel_correlation` with Qwen and SENTINEL from a fresh state. Show the model/tool identifier,
`alert_read`, `intel_search`, final response, task success, and matching receipt/state events. If a
fresh run is unavailable during the backup take, load the committed Qwen trace and say explicitly
that it is a captured local run being replayed—not live or adaptive execution. Briefly show the
finance Qwen trace to establish a second domain, without hiding its run status.

### 1:35-3:10 — Uninterrupted attack reaches the defense

Show the terminal completing the matched `allow_all` and SENTINEL runs without edits or cuts. Then
load the resulting SENTINEL `enterprise_direct_token_request` trace and use **Compare run** for the
matched `allow_all` trace. Walk chronologically through:

1. Briefly show the paired `allow_all` trace executing unauthorized `wiki_search` with
   `attack_success=true`; this proves the attack is reachable rather than vacuous.
2. Switch to the SENTINEL trace. Qwen reads the legitimate message and drafts the internal update.
3. Injected content causes the same `wiki_search` proposal class.
4. SENTINEL evaluates all applicable gates and returns `BLOCK` with
   `POLICY_TOOL_DENIED` and `TASK_CAPABILITY_DENIED`.
5. No guarded executor receipt exists for the blocked action; there is no external send or
   data-flow violation.

Do not claim task success: explicitly show the grader failure caused by Qwen paraphrasing the
literal date. If the live Qwen control did not reach the attack, switch to the mock pair, label that
switch on screen, and make no Qwen defense-effectiveness claim for that scenario.

### 3:10-4:15 — Lifecycle, approval, rewrite, and trace integrity

Load the committed outcome probes. Use presenter mode and the decision arrows. Show the email action first returning `ESCALATE`, the protected
approval record, full revalidation, receipt, and state change. Then show the restricted-send
`REWRITE`, its redacted `email_draft`, and the second G1-G7 result. Explain that payment and
remediation paths use the same authoritative prepare → confirm → execute pattern. Point to the shared
action digest, policy hash/version, ToolSpec version, normalizer version, receipt, and verified state.
Call this digest-linked trace continuity, not cryptographic non-repudiation. Say that the viewer
shows only emitted stages; it does not invent a separate event for the executor's in-memory permit.

### 4:15-5:25 — Comparative evidence

Use **Compare run** for the two encoded-exfil traces. The provenance baseline permits the Base64 protected
value to reach an unauthorized sink; SENTINEL recognizes the transformed value and blocks it. Show
the validation result table: provenance ASR 0.25/CVR 0.111 versus SENTINEL ASR/CVR 0.0, both with
BTU 1.0. Then show whole-context versus field-aware asset criticality: conservative taint lowers
validation BTU to 0.8, field-aware remains 1.0.

Open the aggregate evidence dashboard for the public/validation scorecards, scenario matrix, and
ablation view. State that the full comparisons use deterministic mock actions and a static scripted
attacker deliberately so each defense sees the same candidate actions and starting state. Point out
the dashboard's evidence-boundary notice: attack-success and legitimacy labels are evaluator-only
post-run fields, never firewall inputs.

### 5:25-6:15 — Observability and authority separation

Demonstrate the decision story, expandable G1-G7 cells, rewrite diff/revalidation, action chain, full
timeline filters, provenance counts, risk/confidence labels, and continuity result. Call risk a
deterministic severity—not a probability—and confidence confidence in runtime facts. State that the
Python verifier is authoritative. If recording a fresh short run, select **Follow live** first to
show the flushed JSONL growing without claiming wall-clock event timestamps.
Show `DecisionContext` fields or its test and explain that scenario ID, filenames, labels, reference
plans, and expected outcomes cannot enter the decision API. Clarify that `task_authorization` is a
simulator-issued stand-in for authenticated RBAC—not authority inferred from user text.

### 6:15-7:00 — Honest limitations and reproducibility

Show the evidence manifest and commit. State:

- a small live Qwen trace set, not a full Qwen aggregate;
- two exact-date utility failures in Qwen traces;
- one non-violating unnecessary draft makes public TUI 0.983;
- two Windows symlink tests skip for privilege error 1314;
- risk values are deterministic severity, not learned probabilities;
- the published aggregates use one deterministic seed and do not establish statistical confidence
  intervals;
- AgentDojo was not run.

End with the exact `uv sync`, `pytest`, `sentinel eval`, and `sentinel replay` commands in the README.

## Backup-take checklist

- 5-10 minutes, readable at normal playback speed.
- One benign Qwen task, one attack reaching SENTINEL, one actual secure outcome.
- G1-G7 decision, reason codes, provenance, destination, and trace links visible.
- Approval/lifecycle and rewrite explained accurately.
- Mock versus Qwen and replay versus adaptive execution labeled on screen.
- Ablation, utility result, and at least one failure/limitation shown.
- Commit, config, model hash, trace names, and scorecard digests match the repository.
