# Offline trace viewer

Open `sentinel-trace-viewer.html` in a browser, then select or drop any JSONL trace produced by
`sentinel run` or `sentinel eval`.

The viewer is a single offline file with no packages, server, or network requests. It provides:

- run outcome and decision/execution counts;
- filters and full-text search over the official event timeline;
- exact event payload inspection;
- digest-linked action chains with G1–G7 gate results and reason codes;
- client-side continuity checks for required link fields, trusted emitters, event order, and paired
  executor receipt/state records.

The Python verifier in `sentinel.firewall.trace` remains authoritative. The viewer does not claim
cryptographic non-repudiation and does not expose model chain-of-thought.
