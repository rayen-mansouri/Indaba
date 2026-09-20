# Responsible-AI and security statement

## Intended use

SENTINEL is a competition prototype for the organizer's offline synthetic simulator. It demonstrates
deterministic authorization, lifecycle, confidentiality, destination, and trace checks at an AI
agent's tool boundary. It is not a general prompt-injection detector, a production banking/SOC
control, or evidence that an LLM is safe in unmodeled environments.

## Human responsibility

The system escalates only when policy permits an action but a bound human decision is missing. The
review surface must show canonical effect, destination, amount, policy condition, and trusted
provenance facts. It must not ask a reviewer to approve free-form attacker narrative. Approval is
one-time and bound to issuer/role, task, canonical action digest, policy and state versions, and
expiry. A fresh approval causes complete revalidation; it is not automatic continuation.

Humans remain responsible for defining policy and authenticated task grants, resolving incomplete
authorization, investigating repeated denied actions, and deciding whether a proposed real-world
deployment is appropriate. Reason codes explain policy facts, not model reasoning.

## Data and privacy

Only fictional simulator data and generated canaries were used. No real accounts, credentials,
personal data, bank/SOC systems, remote inference APIs, or operational destinations were accessed.
The defense observes proposed actions, their payloads/destinations, recent live agent state,
runtime provenance, active policy, and authenticated workflow state. It stores these in local JSONL
evidence, so a production adaptation must apply access control, retention limits, and redaction
appropriate to the trace's most sensitive payload.

Model weights, LM Studio state, Hugging Face caches, `.env` files, and secrets are excluded from the
repository. Chain-of-thought is neither requested for observability nor persisted; only final
actions, gate facts, severity, confidence, and short reason codes are recorded.

## Expected harms and costs

- Incomplete task grants can cause false blocks and prevent time-sensitive legitimate work.
- Escalation consumes reviewer attention and may produce automation bias if presented poorly.
- A permitted draft or note can still carry attacker-authored social-engineering text even when no
  protected value leaks and no message is sent.
- Runtime policy mistakes can systematically authorize or deny the wrong class of action.
- Deterministic severity scores may be mistaken for population probabilities; they are not.
- Logs can become a secondary confidential sink if deployed without access and retention controls.

The safe failure mode is non-execution. Crashes, parse failures, timeouts, malformed metadata,
unknown tools/sensitivity, missing provenance, and trace discontinuity never count as successful
defense runs. A missing authenticated task envelope is converted into an empty protected scope and
a traced `TASK_AUTH_MISSING` block; it does not become authority and does not crash the evaluator.

Memory separation is a boundary property, not a semantic claim that one gate understands memory.
The protected stores and G1/G2/G4 prevent model-visible memory from minting authority or approval;
G5 narrowly checks the runtime-owned task authenticator. Read-tool sensitivity normally comes from
each synthetic fixture record's `_meta`; the one baked field contract is
`asset_lookup.service_account_token` in the trusted ToolSpec overlay. These labels are propagated
through observed transformations and do not consult evaluator canaries.

## Evaluation boundaries

The full paired comparison uses a deterministic mock model so defenses receive identical candidate
actions. A small live Qwen3-8B trace set, including one non-vacuous `allow_all`/SENTINEL control,
supplements but does not replace that controlled experiment. The 28 scenarios are synthetic and
repository-visible. Results do not support broad claims about other models, languages, users,
domains, adaptive attackers, or production networks.

Two Windows symlink tests are skipped because this host lacks symlink privilege. AgentDojo was not
run. MITRE ATLAS is used only as reporting taxonomy. All bypasses and task failures must remain in
the evidence rather than being relabeled as safe outcomes.

## Deployment checklist

Before any use beyond the competition simulator:

1. Replace scenario authorization with an authenticated identity/RBAC/workflow service; never infer
   authority from natural-language goals.
2. Review every ToolSpec and adapter against the real tool's complete effect and destination set.
3. Secure policy, approval, trace, and authoritative state stores with transactional access control.
4. Add signed append-only storage before claiming non-repudiation.
5. Test representative languages, payload types, aliases, nested recipients, attachments, and
   multi-session transformations.
6. Establish reviewer staffing, escalation timeouts, safe cancellation, appeal, and incident
   response procedures.
7. Red-team the deployment and monitor false blocks, unauthorized effects, reviewer load, domain
   performance, trace access, and policy drift.
