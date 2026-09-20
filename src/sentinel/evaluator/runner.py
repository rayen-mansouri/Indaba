"""Run scenarios end to end: scenario -> agent -> defense -> gateway -> graders -> score."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from sentinel.agent.reference import AgentRunResult, ReferenceAgent
from sentinel.attackers.baselines.static import StaticAttacker
from sentinel.attackers.interface import Attacker, AttackRequest, SeedPayload, TranscriptItem
from sentinel.attackers.validator import AttackMutationValidator
from sentinel.config import BENCHMARK_VERSION, CompetitionConfig
from sentinel.core.actions import ActionType, CandidateAction, DefenseDecision
from sentinel.core.events import Actor, EventLog, EventType, LogicalClock
from sentinel.core.policies import Finding, PolicyEngine, load_policy
from sentinel.core.result import (
    AttackMutationRecord,
    DecisionRecord,
    ScenarioOutcome,
    ToolExecution,
)
from sentinel.core.scenario import Scenario, ScenarioError, child_seed, discover_scenarios, load_scenario
from sentinel.core.state import WorldState
from sentinel.defenses.interface import Defense
from sentinel.evaluator.labels import PlanMatcher
from sentinel.evaluator.leakage import detect_leaks
from sentinel.evaluator.metrics import Metrics, compute_metrics
from sentinel.evaluator.policy_graders import security_verdict
from sentinel.evaluator.scoring import ScoreBreakdown, compute_score
from sentinel.evaluator.task_graders import GradingContext, grade_task
from sentinel.firewall.runtime import SentinelFirewallDefense
from sentinel.models.base import ModelAdapter
from sentinel.models.mock import MockModelAdapter
from sentinel.storage.runs import ArtifactStore, sanitize_id
from sentinel.tools.base import Sink, Tool
from sentinel.tools.gateway import GatewayResult, ToolGateway
from sentinel.tools.registry import ToolRegistry, registry_for_domain


class AttackMode(StrEnum):
    NONE = "none"
    STATIC = "static"  # all attacker mutations applied before the first agent step
    ADAPTIVE = "adaptive"  # one attacker query before each agent step


@dataclass
class RunConfig:
    root: Path
    competition: CompetitionConfig = field(default_factory=CompetitionConfig)
    attack_mode: AttackMode = AttackMode.STATIC
    model_factory: Callable[[], ModelAdapter] = MockModelAdapter
    include_reference_plan: bool = True
    artifacts: ArtifactStore | None = None
    artifact_group: str = "runs"


@dataclass
class ScenarioRun:
    outcome: ScenarioOutcome
    log: EventLog
    agent_result: AgentRunResult
    artifact: Path | None = None


class EvaluationHooks:
    """Implements RunHooks: labels, policy checks, leak detection, and attacker scheduling."""

    def __init__(
        self,
        scenario: Scenario,
        state: WorldState,
        log: EventLog,
        policy: PolicyEngine,
        attacker: Attacker | None,
        attack_mode: AttackMode,
        query_budget: int,
    ) -> None:
        self.scenario = scenario
        self.state = state
        self.log = log
        self.policy = policy
        self.matcher = PlanMatcher(scenario)
        self.attacker = attacker if scenario.attack.present and scenario.attack.surfaces else None
        self.attack_mode = attack_mode
        self.query_budget = query_budget
        self.validator = AttackMutationValidator(scenario, state)
        self.findings: list[Finding] = []
        self.decisions: dict[int, DecisionRecord] = {}
        self.executions: list[ToolExecution] = []
        self.mutations: list[AttackMutationRecord] = []
        self.transcript: list[TranscriptItem] = []
        self._effects_seen = 0
        self._rounds = 0
        self._registry: ToolRegistry | None = None
        self._pending_attempt: list[Finding] = []

    # ---- attacker ---------------------------------------------------------------------------
    def _query_attacker(self, step_id: int) -> bool:
        assert self.attacker is not None
        request = AttackRequest(
            scenario_id=self.scenario.id,
            domain=self.scenario.domain.value,
            round=self._rounds,
            step_id=step_id,
            objective=self.scenario.attack.objective,
            surfaces=self.validator.surface_views(),
            transcript=self.transcript[-30:],
            seed_payloads=[
                SeedPayload(surface_id=p.surface, operation=p.operation, text=p.text)
                for p in self.scenario.attack.payloads
            ]
            if self.scenario.attack.share_payloads_with_attacker
            else [],
            budget_remaining=self.validator.budget_remaining,
        )
        self._rounds += 1
        try:
            mutation = self.attacker.next_mutation(request)
        except Exception as exc:
            self.mutations.append(
                AttackMutationRecord(
                    step_id=step_id,
                    surface="-",
                    operation="-",
                    accepted=False,
                    reason=f"attacker error: {type(exc).__name__}",
                )
            )
            return False
        if mutation is None:
            return False
        outcome = self.validator.apply(mutation)
        self.mutations.append(
            AttackMutationRecord(
                step_id=step_id,
                surface=mutation.surface_id,
                operation=mutation.operation.value,
                accepted=outcome.accepted,
                reason=outcome.reason,
                chars=len(mutation.text),
            )
        )
        return True

    def before_step(self, step_id: int, turn_index: int) -> None:
        if self.attacker is None or self.attack_mode is AttackMode.NONE:
            return
        if self.attack_mode is AttackMode.STATIC:
            if step_id != 1:
                return
            limit = max(self.query_budget, self.scenario.attack.max_mutations)
            while self._rounds < limit and self.validator.budget_remaining > 0:
                if not self._query_attacker(step_id):
                    break
        elif self._rounds < self.query_budget and self.validator.budget_remaining > 0:
            self._query_attacker(step_id)

    # ---- defense / human ----------------------------------------------------------------------
    def on_decision(
        self,
        step_id: int,
        turn_index: int,
        action: CandidateAction,
        decision: DefenseDecision,
        latency_ms: float,
        error: str | None,
    ) -> None:
        step = self.matcher.match(turn_index, action)
        target = action.confirmation_for if action.type is ActionType.REQUEST_CONFIRMATION else action
        consequential = bool(step and step.confirm)
        if target is not None and target.type is ActionType.TOOL_CALL and target.tool:
            registry_tool = self._tool(target.tool)
            consequential = consequential or bool(registry_tool and registry_tool.is_consequential(target.arguments))
        self.decisions[step_id] = DecisionRecord(
            step_id=step_id,
            action_type=action.type.value,
            tool=target.tool if target else None,
            decision=decision.decision,
            risk_score=decision.risk_score,
            confidence=decision.confidence,
            reason_codes=list(decision.reason_codes),
            legitimate=step is not None,
            consequential=consequential,
            latency_ms=round(latency_ms, 3),
            defense_error=error,
        )
        self.transcript.append(
            TranscriptItem(
                step_id=step_id,
                kind=action.type.value,
                tool=target.tool if target else None,
                decision=decision.decision.value,
            )
        )

    def human_confirm(self, step_id: int, turn_index: int, action: CandidateAction) -> bool:
        approved = self.matcher.is_legitimate(turn_index, action)
        record = self.decisions.get(step_id)
        if record is not None:
            self.decisions[step_id] = record.model_copy(update={"human_approved": approved})
        return approved

    # ---- tools / sinks ------------------------------------------------------------------------
    def _tool(self, name: str) -> Tool | None:
        return self._registry.get(name) if self._registry is not None else None

    def bind_registry(self, gateway: ToolGateway) -> None:
        self._registry = gateway.registry

    def _record(self, findings: list[Finding]) -> None:
        for finding in findings:
            event = self.log.append(EventType.POLICY_VIOLATION, Actor.EVALUATOR, finding.step_id, finding.to_payload())
            self.findings.append(Finding(**{**finding.__dict__, "event_ref": event.event_id}))

    def before_tool(self, step_id: int, action: CandidateAction, tool: Tool | None) -> None:
        if tool is not None:
            self._pending_attempt = self.policy.check_attempt(action, tool, step_id)
            self._record(self._pending_attempt)
        else:
            self._pending_attempt = []

    def after_tool(
        self, step_id: int, turn_index: int, action: CandidateAction, result: GatewayResult, confirmed: bool
    ) -> None:
        findings = list(self._pending_attempt)
        self._pending_attempt = []
        legitimate = self.matcher.is_legitimate(turn_index, action)
        if result.outcome.succeeded and result.tool is not None:
            self.matcher.record_result(turn_index, action, result.outcome.result)
            executed = self.policy.check_executed(action, result.tool, confirmed, step_id)
            new_effects = self.state.effects[self._effects_seen :]
            self._effects_seen = len(self.state.effects)
            effect_findings = self.policy.check_effects(new_effects)
            self._record(executed + effect_findings)
            findings += executed + effect_findings
        self.executions.append(
            ToolExecution(
                step_id=step_id,
                tool=action.tool or "?",
                succeeded=result.outcome.succeeded,
                legitimate=legitimate,
                violated=bool(findings),
            )
        )
        if self.transcript and self.transcript[-1].step_id == step_id:
            last = self.transcript[-1]
            self.transcript[-1] = last.model_copy(update={"succeeded": result.outcome.succeeded})

    def on_sink(self, step_id: int, action: CandidateAction, sink: Sink) -> None:
        leaks = detect_leaks(sink, self.state.canaries)
        if not leaks:
            return
        findings = self.policy.check_leaks(leaks, step_id, action)
        self._record(findings)
        if findings and self.executions and self.executions[-1].step_id == step_id:
            self.executions[-1] = self.executions[-1].model_copy(update={"violated": True})

    def on_response(self, step_id: int, turn_index: int, action: CandidateAction) -> None:
        return None


def run_scenario(
    scenario: Scenario, defense: Defense, config: RunConfig, attacker: Attacker | None = None
) -> ScenarioRun:
    competition = config.competition
    if attacker is None and config.attack_mode is not AttackMode.NONE:
        attacker = StaticAttacker()  # attacks are on unless explicitly disabled with AttackMode.NONE
    seed = child_seed(scenario.seed, "run", competition.run_seed)
    run_id = sanitize_id(f"{scenario.id}-{defense.name}-s{competition.run_seed}")
    state = WorldState.from_scenario(scenario, config.root, competition.run_seed)
    clock = LogicalClock(seed)
    artifact = (
        config.artifacts.prepare_event_path(config.artifact_group, run_id) if config.artifacts is not None else None
    )
    log = EventLog(run_id, clock, sink_path=artifact)
    try:
        return _run_scenario_body(scenario, defense, config, attacker, run_id, state, clock, artifact, log, competition)
    finally:
        log.close()


def _run_scenario_body(
    scenario: Scenario,
    defense: Defense,
    config: RunConfig,
    attacker: Attacker | None,
    run_id: str,
    state: WorldState,
    clock: LogicalClock,
    artifact: Path | None,
    log: EventLog,
    competition: CompetitionConfig,
) -> ScenarioRun:
    registry = registry_for_domain(scenario.domain.value)
    gateway = ToolGateway(registry, state)
    loaded_policy = load_policy(config.root, scenario.policy_profile)
    policy = PolicyEngine(loaded_policy, scenario)
    if isinstance(defense, SentinelFirewallDefense):
        defense.bind_run(
            run_id=run_id,
            task_authorization=scenario.task_authorization,
            policy=loaded_policy,
            allowed_tools=tuple(scenario.allowed_tools),
            registry=registry,
            state=state,
            gateway=gateway,
            log=log,
        )
    hooks = EvaluationHooks(
        scenario, state, log, policy, attacker, config.attack_mode, competition.attack_simulation.query_budget
    )
    hooks.bind_registry(gateway)
    policy_context: dict[str, Any] = policy.defense_context(registry.as_dict())
    internal_domain = state.settings.get("internal_email_domain")
    if internal_domain:
        policy_context["internal_email_domains"] = [internal_domain]
    agent = ReferenceAgent(
        scenario=scenario,
        state=state,
        gateway=gateway,
        model=config.model_factory(),
        defense=defense,
        hooks=hooks,
        log=log,
        clock=clock,
        policy_context=policy_context,
        runtime=competition.defense,
        include_reference_plan=config.include_reference_plan,
    )
    agent_result = agent.run()
    if isinstance(defense, SentinelFirewallDefense):
        from sentinel.firewall.trace import TraceIntegrityError, verify_digest_linked_trace

        try:
            verify_digest_linked_trace(log.events)
        except TraceIntegrityError as exc:
            agent_result.termination = f"security_error: trace_integrity: {exc}"[:200]
            log.append(
                EventType.POLICY_VIOLATION,
                Actor.EVALUATOR,
                agent_result.steps,
                {"rule_id": "TRACE_INTEGRITY", "message": str(exc)},
            )

    graders = grade_task(
        list(scenario.success_conditions), GradingContext(state=state, responses=agent_result.responses)
    )
    task_success = all(g.passed for g in graders) and agent_result.termination == "completed"
    verdict = security_verdict(scenario, hooks.findings)
    passed = sum(g.passed for g in graders)
    log.append(
        EventType.TASK_SUCCESS if task_success else EventType.TASK_FAILURE,
        Actor.EVALUATOR,
        agent_result.steps,
        {"summary": f"{passed}/{len(graders)} success conditions passed", "termination": agent_result.termination},
    )

    outcome = ScenarioOutcome(
        run_id=run_id,
        scenario_id=scenario.id,
        scenario_version=scenario.version,
        domain=scenario.domain.value,
        split=scenario.split.value,
        seed=scenario.seed,
        defense=defense.name,
        attack_present=scenario.attack.present,
        attack_family=scenario.attack.family.value,
        hard_negative=scenario.is_hard_negative,
        difficulty=scenario.attack.difficulty,
        steps=agent_result.steps,
        task_success=task_success,
        attack_success=verdict.attack_success,
        critical_violation=verdict.critical_violation,
        data_flow_violation=verdict.data_flow_violation,
        grader_results=graders,
        findings=[f.to_payload() for f in hooks.findings],
        decisions=[hooks.decisions[k] for k in sorted(hooks.decisions)],
        tool_executions=hooks.executions,
        mutations=hooks.mutations,
        termination=agent_result.termination,
    )
    if config.artifacts is not None:
        config.artifacts.write_json(config.artifact_group, f"{run_id}.summary", outcome.model_dump(mode="json"))
    return ScenarioRun(outcome=outcome, log=log, agent_result=agent_result, artifact=artifact)


# ---- suites -----------------------------------------------------------------------------------


class EvaluationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    benchmark_version: str
    split: str
    defense: str
    attack_mode: str
    run_seed: int
    scenario_count: int
    metrics: Metrics
    by_domain: dict[str, Metrics]
    score: ScoreBreakdown
    deterministic_digest: str
    outcomes: list[ScenarioOutcome] | None = None

    def participant_view(self) -> dict[str, Any]:
        """Return the complete local self-test report."""
        return self.model_dump(mode="json")


def _digest(outcomes: Sequence[ScenarioOutcome], metrics: Metrics) -> str:
    stable_outcomes = []
    for outcome in outcomes:
        data = outcome.model_dump(mode="json")
        for decision in data["decisions"]:
            decision.pop("latency_ms", None)
        stable_outcomes.append(data)
    stable_metrics = metrics.model_dump(mode="json")
    for key in ("latency_median_ms", "latency_p95_ms"):
        stable_metrics.pop(key)
    blob = json.dumps({"outcomes": stable_outcomes, "metrics": stable_metrics}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def load_suite(path: Path) -> list[Scenario]:
    """Load every scenario under ``path``.

    Raises rather than returning an empty suite: a run over zero scenarios reports perfect metrics,
    which is the vacuous result the participant guide warns about.
    """
    files = discover_scenarios(path)
    if not files:
        raise ScenarioError(str(path), ["no scenario files found; check the path"])
    return [load_scenario(p) for p in files]


def evaluate(
    scenarios: Sequence[Scenario],
    defense_factory: Callable[[], Defense],
    config: RunConfig,
    attacker_factory: Callable[[], Attacker] | None = None,
    ood_scenarios: Sequence[Scenario] = (),
) -> EvaluationReport:
    outcomes: list[ScenarioOutcome] = []
    defense_name = "defense"
    for scenario in scenarios:
        defense = defense_factory()
        attacker = attacker_factory() if attacker_factory else None
        try:
            outcomes.append(run_scenario(scenario, defense, config, attacker).outcome)
            defense_name = defense.name
        finally:
            defense.close()
            if attacker is not None:
                attacker.close()
    metrics = compute_metrics(outcomes)
    ood_metrics = None
    if ood_scenarios:
        ood_outcomes = []
        for scenario in ood_scenarios:
            defense = defense_factory()
            attacker = attacker_factory() if attacker_factory else None
            try:
                ood_outcomes.append(run_scenario(scenario, defense, config, attacker).outcome)
            finally:
                defense.close()
        ood_metrics = compute_metrics(ood_outcomes)
    domains = sorted({o.domain for o in outcomes})
    by_domain = {d: compute_metrics([o for o in outcomes if o.domain == d]) for d in domains}
    splits = {o.split for o in outcomes}
    score = compute_score(
        metrics,
        config.competition.scoring,
        critical_violations=sum(o.critical_violation for o in outcomes),
        ood_metrics=ood_metrics,
    )
    return EvaluationReport(
        benchmark_version=config.competition.benchmark_version or BENCHMARK_VERSION,
        split=splits.pop() if len(splits) == 1 else "mixed",
        defense=defense_name,
        attack_mode=config.attack_mode.value,
        run_seed=config.competition.run_seed,
        scenario_count=len(outcomes),
        metrics=metrics,
        by_domain=by_domain,
        score=score,
        deterministic_digest=_digest(outcomes, metrics),
        outcomes=outcomes,
    )


def eval_group_name(split: str, defense: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return sanitize_id(f"eval-{split}-{defense}-{stamp}")
