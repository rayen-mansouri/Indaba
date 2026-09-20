# Offline trace viewer

Open `sentinel-trace-viewer.html` in a browser, then select or drop any JSONL trace produced by
`sentinel run` or `sentinel eval`.

The viewer is a single offline file with no packages, server, or network requests. It is intended to
be the primary observability surface in the submission video, while `sentinel replay` and the Python
verifier remain the authoritative machine checks. It provides:

- a decision-story view with plain-language reason codes and the actual secure outcome;
- a clickable G1–G7 matrix, deterministic severity, runtime-fact confidence, and provenance counts;
- policy-owned rewrite diffs plus the replacement's independent gate revalidation;
- protected simulated-approval details, guarded receipts, and verified state changes;
- presenter mode, keyboard playback (`←`, `→`, `Space`), speed control, and caption sidecars;
- paired JSONL comparison aligned by logical step and executed/requested tool;
- multi-scorecard comparison with BTU/ASR/CVR/FBR/TUI and domain/attack-family breakdowns;
- filters, search, and exact payload inspection over the full official timeline;
- live follow for a growing JSONL file in Chrome/Edge via the File System Access API;
- digest-linked action chains with G1–G7 results and reason codes;
- client-side continuity checks for required link fields, trusted emitters, event order, and paired
  executor receipt/state records.

The Python verifier in `sentinel.firewall.trace` remains authoritative. The viewer does not claim
cryptographic non-repudiation and does not expose model chain-of-thought. It displays only emitted
stages: the guarded executor's in-memory permit is intentionally not invented as a trace event.

## Video workflow

1. Open the HTML file in Chrome or Edge.
2. Select **Follow live** before starting a run, then choose the JSONL path inside the prepared
   artifact directory. The runner appends and flushes each event, and the viewer refreshes when the
   file grows. If the browser does not support live follow, reopen the same file after the run.
3. Load the SENTINEL trace as primary and the matched baseline with **Compare run**.
4. Load one or more scorecard JSON files with **Scorecards**.
5. Load `video-captions.example.json` with **Captions**, enter presenter mode, and use the arrow keys
   or autoplay to advance through decisions.

Caption files may be an array, or `{ "captions": [...] }`. Each item is `{ "seq": number,
"text": string }`; the last caption whose `seq` is not greater than the selected decision is shown.
