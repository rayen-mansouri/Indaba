"""In-process baseline defenses."""

from __future__ import annotations

from collections.abc import Callable

from sentinel.defenses.baselines.allow_all import AllowAllDefense
from sentinel.defenses.baselines.deny_sensitive import DenySensitiveDefense
from sentinel.defenses.baselines.heuristic_risk import HeuristicRiskDefense
from sentinel.defenses.baselines.keyword import KeywordDefense
from sentinel.defenses.baselines.provenance import ProvenanceDefense
from sentinel.defenses.interface import Defense
from sentinel.firewall.runtime import SentinelFirewallDefense

BASELINES: dict[str, Callable[[], Defense]] = {
    "allow_all": AllowAllDefense,
    "deny_sensitive": DenySensitiveDefense,
    "keyword": KeywordDefense,
    "heuristic_risk": HeuristicRiskDefense,
    "provenance": ProvenanceDefense,
    "sentinel": SentinelFirewallDefense,
}


def get_baseline(name: str) -> Defense:
    key = name.replace("-", "_")
    if key not in BASELINES:
        raise KeyError(f"unknown baseline {name!r}; choose from {', '.join(sorted(BASELINES))}")
    return BASELINES[key]()
