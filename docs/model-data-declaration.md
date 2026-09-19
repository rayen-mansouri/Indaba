# Model and data declaration

Evidence date: 19 September 2026

## Reference model

- Model: `qwen/qwen3-8b` (organizer-required Qwen3-8B).
- Local artifact: `Qwen3-8B-Q4_K_M.gguf`.
- SHA-256: `a7676d257b10f3ce23aedba45e64ba61a5aa295f0009d87c5627f6c026a8f35f`.
- Runtime: LM Studio local OpenAI-compatible API; identifier `sentinel-qwen3-8b`.
- Context: 8,192 tokens.
- Maximum generation: 2,048 tokens.
- Sampling: temperature 0, seed 0.
- Device request: LM Studio `--gpu max` on an NVIDIA RTX 4060 Laptop GPU; Intel i7-13620H host.
- System prompt: exact organizer `SYSTEM_PROMPT`; no added safety instruction.
- Tools: the organizer's 25 registered tools with their existing strict Pydantic-derived JSON
  schemas; no tool was added or removed.
- Thinking: runtime-managed Qwen reasoning may be returned in a separate API field. The adapter
  ignores it and records only the final JSON action; chain-of-thought is not persisted.

No model fine-tuning, adapter training, classifier training, or external inference API was used.
The quantized local artifact is not committed to the repository.

## Deterministic evaluation model

The full paired public/validation comparisons use the starter kit's deterministic `mock` model,
seed 0. It follows organizer reference plans to supply identical candidate actions to each defense.
Reference plans are evaluator/model fixtures and never enter the SENTINEL decision or policy API.
Mock results are labeled as controlled local diagnostics, not live-model performance.

## Data

- Benchmark: repository-provided `sentinel-bench/0.1.0`.
- Inventory: 19 public and 9 validation scenarios across enterprise, finance, and SOC.
- Fixtures: synthetic fictional organizations, people, accounts, email addresses, cases, alerts,
  payments, documents, notes, and memory entries.
- Secret detection: deterministic synthetic canaries only.
- Attack content: repository-provided synthetic payloads and offline mutation variants.
- External training/evaluation datasets: none.
- AgentDojo: not run.
- Real personal, credential, banking, security-operations, or organizer data: none.

The validation split is repository-visible and is used for regression/ablation evidence, not an
unseen-test or generalization claim.

## Related-work declarations

AgentSpec and AgentDojo are cited as related work only. No external paper's experimental result,
dataset, model, or implementation was reproduced. MITRE ATLAS content release `v2026.09`, accessed
19 September 2026, is used only as reporting taxonomy and never enters a policy decision or model
training.
