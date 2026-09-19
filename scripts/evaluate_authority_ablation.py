"""Evaluate SENTINEL with coarse role-like grants instead of task-specific grants.

This is an intentionally weaker authorization ablation. It helps distinguish the
firewall's provenance/lifecycle/confidentiality controls from the benefit supplied
by a narrowly scoped authenticated task envelope.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.core.scenario import Scenario, TaskAuthorizationSpec, TaskGrantSpec
from sentinel.evaluator.runner import RunConfig, evaluate, load_suite
from sentinel.firewall.runtime import SentinelFirewallDefense
from sentinel.firewall.toolspecs import build_official_tool_manifest
from sentinel.storage.runs import ArtifactStore

ROOT = Path(__file__).resolve().parents[1]


def coarse_authority(scenario: Scenario) -> TaskAuthorizationSpec:
    authority = scenario.task_authorization
    if authority is None:
        raise ValueError(f"{scenario.id} has no authenticated task authority")
    manifest = build_official_tool_manifest()
    grants: list[TaskGrantSpec] = []
    for tool_name in scenario.allowed_tools:
        spec = manifest.get(tool_name)
        if spec is None:
            raise ValueError(f"no ToolSpec for {tool_name}")
        grants.append(
            TaskGrantSpec(
                tool=tool_name,
                capabilities=list(spec.capabilities),
                resources=["*"] if spec.resource_fields else [],
                destinations=["*"] if spec.destination_fields else [],
                max_amount=1_000_000_000 if spec.amount_fields else None,
                currency="TND" if spec.amount_fields else None,
            )
        )
    return authority.model_copy(update={"grants": grants})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("split", choices=("public", "validation"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--artifacts", type=Path)
    args = parser.parse_args()
    scenarios = [
        scenario.model_copy(update={"task_authorization": coarse_authority(scenario)})
        for scenario in load_suite(ROOT / "scenarios" / args.split)
    ]
    report = evaluate(
        scenarios,
        SentinelFirewallDefense,
        RunConfig(
            root=ROOT,
            include_reference_plan=True,
            artifacts=ArtifactStore(args.artifacts) if args.artifacts else None,
            artifact_group=f"authority-ablation-{args.split}",
        ),
    )
    result = report.participant_view()
    result["ablation"] = "coarse_authenticated_authority"
    body = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body, encoding="utf-8")
    print(body, end="")


if __name__ == "__main__":
    main()
