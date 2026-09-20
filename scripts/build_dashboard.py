"""Build the offline SENTINEL dashboard (observability/sentinel-dashboard.html).

Embeds every scorecard under evidence/results, the Qwen run summaries under evidence/traces, the
manifest and block attribution into one self-contained HTML file. No server, no network.

    python scripts/build_dashboard.py                       # evidence bundle only
    python scripts/build_dashboard.py --extra colab_out/    # also include fresh scorecards/summaries
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTCOME_KEYS = (
    "scenario_id", "domain", "attack_family", "attack_present", "attack_success", "task_success",
    "critical_violation", "data_flow_violation", "steps", "termination", "grader_results", "findings",
)
DECISION_KEYS = (
    "step_id", "tool", "action_type", "decision", "risk_score", "confidence", "reason_codes",
    "legitimate", "consequential", "latency_ms", "human_approved", "defense_error",
)
TOP_KEYS = ("split", "defense", "attack_mode", "ablation", "deterministic_digest", "metrics", "by_domain", "score")


def slim_decisions(decisions: list[dict]) -> list[dict]:
    return [{k: d.get(k) for k in DECISION_KEYS} for d in decisions]


def slim_scorecard(sc: dict) -> dict:
    out = {k: sc[k] for k in TOP_KEYS if k in sc}
    outcomes = []
    for o in sc.get("outcomes", []):
        item = {k: o.get(k) for k in OUTCOME_KEYS}
        item["decisions"] = slim_decisions(o.get("decisions", []))
        item["findings"] = [str(f)[:300] for f in (o.get("findings") or [])]
        outcomes.append(item)
    out["outcomes"] = outcomes
    return out


def is_scorecard(d: object) -> bool:
    return isinstance(d, dict) and "outcomes" in d and "metrics" in d


def is_summary(d: object) -> bool:
    return isinstance(d, dict) and "scenario_id" in d and isinstance(d.get("decisions"), list)


def load_summary(path: Path, group: str) -> dict:
    d = json.loads(path.read_text(encoding="utf-8"))
    keys = ("scenario_id", "domain", "defense", "attack_family", "attack_present", "attack_success", "task_success")
    return {"group": group, **{k: d.get(k) for k in keys}, "decisions": slim_decisions(d["decisions"])}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", type=Path, default=ROOT / "evidence")
    ap.add_argument("--extra", type=Path, action="append", default=[], help="extra scorecard/summary file or dir")
    ap.add_argument("--out", type=Path, default=ROOT / "observability" / "sentinel-dashboard.html")
    args = ap.parse_args()

    runs, qwen = [], []
    for f in sorted((args.evidence / "results").glob("*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        if is_scorecard(d):
            runs.append({"label": f.stem, "data": slim_scorecard(d)})

    for f in sorted((args.evidence / "traces").rglob("*.summary.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        if is_summary(d):
            qwen.append(load_summary(f, f.parent.name if f.parent.name.startswith("qwen") else "outcomes"))

    for extra in args.extra:
        files = sorted(extra.rglob("*.json")) if extra.is_dir() else [extra]
        for f in files:
            d = json.loads(f.read_text(encoding="utf-8"))
            if is_scorecard(d):
                runs.append({"label": f.stem, "data": slim_scorecard(d)})
            elif is_summary(d):
                qwen.append(load_summary(f, "extra"))

    data = {"runs": runs, "qwen": qwen}
    manifest = args.evidence / "manifest.json"
    if manifest.exists():
        data["manifest"] = json.loads(manifest.read_text(encoding="utf-8"))
    attribution = args.evidence / "results" / "block-attribution.json"
    if attribution.exists():
        ba = json.loads(attribution.read_text(encoding="utf-8"))
        data["block_attribution"] = {k: ba.get(k) for k in ("summary", "method", "top_reason_codes", "blocks_by_tool")}

    template = (ROOT / "observability" / "dashboard_template.html").read_text(encoding="utf-8")
    marker = "/*__DATA__*/null"
    if marker not in template:
        raise SystemExit("template marker missing")
    payload = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    args.out.write_text(template.replace(marker, payload, 1), encoding="utf-8")
    print(f"wrote {args.out} ({args.out.stat().st_size // 1024} KB, {len(runs)} scorecards, {len(qwen)} run summaries)")


if __name__ == "__main__":
    main()
