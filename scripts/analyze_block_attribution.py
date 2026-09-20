"""Attribute SENTINEL blocks using evaluator-only post-run labels.

This analysis consumes frozen scorecards after evaluation. The ``legitimate`` field is grader
metadata and is deliberately unavailable to the defense decision path.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


def _scenario_tools(root: Path) -> dict[str, set[str]]:
    tools: dict[str, set[str]] = {}
    for path in root.rglob("*.yaml"):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and document.get("id"):
            tools[str(document["id"])] = {str(tool) for tool in document.get("allowed_tools", [])}
    return tools


def analyze(paths: list[Path], scenario_root: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    by_tool: Counter[str] = Counter()
    by_reason: Counter[str] = Counter()
    scenario_tools = _scenario_tools(scenario_root)
    attacked_scenarios: dict[str, list[bool]] = {}

    for path in paths:
        card = json.loads(path.read_text(encoding="utf-8"))
        for outcome in card.get("outcomes", []):
            for decision in outcome.get("decisions", []):
                if decision.get("decision") != "block":
                    continue
                tool = decision.get("tool") or decision.get("action_type") or "unknown"
                reasons = list(decision.get("reason_codes", []))
                legitimate = bool(decision.get("legitimate"))
                scenario_id = str(outcome.get("scenario_id"))
                organizer_tool_allowed = str(tool) in scenario_tools.get(scenario_id, set())
                by_tool[str(tool)] += 1
                by_reason.update(str(reason) for reason in reasons)
                if outcome.get("attack_present"):
                    attacked_scenarios.setdefault(scenario_id, []).append(organizer_tool_allowed)
                rows.append(
                    {
                        "split": outcome.get("split"),
                        "scenario_id": scenario_id,
                        "attack_present": outcome.get("attack_present"),
                        "hard_negative": outcome.get("hard_negative"),
                        "step_id": decision.get("step_id"),
                        "tool": tool,
                        "organizer_tool_allowed": organizer_tool_allowed,
                        "boundary_attribution": (
                            "sentinel_gate_within_organizer_tools"
                            if organizer_tool_allowed
                            else "outside_organizer_allowed_tools"
                        ),
                        "grader_legitimate": legitimate,
                        "attribution": "legitimate" if legitimate else "unauthorized_or_attack_driven",
                        "reason_codes": reasons,
                    }
                )

    legitimate_blocks = sum(row["grader_legitimate"] for row in rows)
    outside_tool_blocks = sum(not row["organizer_tool_allowed"] for row in rows)
    boundary_only_scenarios = sorted(
        scenario_id for scenario_id, allowed in attacked_scenarios.items() if allowed and not any(allowed)
    )
    sentinel_gate_scenarios = sorted(set(attacked_scenarios) - set(boundary_only_scenarios))
    return {
        "method": (
            "Post-run attribution from scorecard decision.legitimate evaluator labels; "
            "these labels are not available to the defense."
        ),
        "inputs": [path.as_posix() for path in paths],
        "summary": {
            "blocks": len(rows),
            "unauthorized_or_attack_driven_blocks": len(rows) - legitimate_blocks,
            "legitimate_blocks": legitimate_blocks,
            "blocks_outside_organizer_allowed_tools": outside_tool_blocks,
            "blocks_within_organizer_allowed_tools": len(rows) - outside_tool_blocks,
            "attacked_scenarios_all_blocks_outside_organizer_tools": len(boundary_only_scenarios),
            "attacked_scenarios_relying_on_sentinel_gates": len(sentinel_gate_scenarios),
        },
        "scenario_attribution": {
            "all_blocks_outside_organizer_allowed_tools": boundary_only_scenarios,
            "at_least_one_block_within_organizer_allowed_tools": sentinel_gate_scenarios,
        },
        "blocks_by_tool": dict(sorted(by_tool.items())),
        "top_reason_codes": dict(by_reason.most_common()),
        "rows": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scorecards", nargs="+", type=Path)
    parser.add_argument("--scenario-root", type=Path, default=Path("scenarios"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = analyze(args.scorecards, args.scenario_root)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
