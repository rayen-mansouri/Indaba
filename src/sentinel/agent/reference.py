"""Event-driven reference agent: model -> defense -> gateway -> event log."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from sentinel.agent.base import (
    AgentContext,
    Feedback,
    FeedbackKind,
    Observation,
    RunHooks,
)
from sentinel.agent.memory import AgentMemory
from sentinel.config import DefenseRuntimeConfig
from sentinel.core.actions import ActionType, CandidateAction, Decision, DefenseDecision
from sentinel.core.events import Actor, EventLog, EventType, LogicalClock
from sentinel.core.provenance import (
    Provenance,
    SourceType,
    TrustLevel,
    least_trusted,
    most_sensitive,
)
from sentinel.core.scenario import Scenario
from sentinel.core.state import WorldState
from sentinel.defenses.client import fail_mode_decision
from sentinel.defenses.interface import (
    ConversationItem,
    Defense,
    DefenseRequest,
    HistoryDigest,
    ObservationView,
    ProvenanceRecord,
    ToolCallSummary,
)
from sentinel.firewall.runtime import SentinelFirewallDefense
from sentinel.models.base import ModelAdapter, ModelError, TurnHints
from sentinel.tools.base import Sink
from sentinel.tools.gateway import ToolGateway

RESPONSE_SINK = "user_response"
MEMORY_SINK = "memory"


@dataclass
class AgentRunResult:
    steps: int
    termination: str
    responses: list[tuple[int, str]] = field(default_factory=list)


class ReferenceAgent:
    def __init__(
        self,
        scenario: Scenario,
        state: WorldState,
        gateway: ToolGateway,
        model: ModelAdapter,
        defense: Defense,
        hooks: RunHooks,
        log: EventLog,
        clock: LogicalClock,
        policy_context: dict[str, object],
        runtime: DefenseRuntimeConfig,
        include_reference_plan: bool = False,
    ) -> None:
        self.scenario = scenario
        self.state = state
        self.gateway = gateway
        self.model = model
        self.defense = defense
        self.hooks = hooks
        self.log = log
        self.clock = clock
        self.policy_context = policy_context
        self.runtime = runtime
        self.include_reference_plan = include_reference_plan
        self.memory = AgentMemory(state)
        self._provenance: dict[str, Provenance] = {}
        self._conversation: list[ConversationItem] = []
        self._observations: list[Observation] = []
        self._tool_calls: list[ToolCallSummary] = []
        self._blocked = 0
        self._escalated = 0
        self._turn_provenance: list[str] = []

    # ---- helpers --------------------------------------------------------------------------
    def _register(self, provenance: list[Provenance]) -> tuple[str, ...]:
        ids = []
        for item in provenance:
            prov_id = f"prov-{len(self._provenance):04d}"
            self._provenance[prov_id] = item
            ids.append(prov_id)
        self._turn_provenance.extend(ids)
        return tuple(ids)

    def _remember(self, role: str, observation: Observation) -> None:
        self._observations.append(observation)
        self._conversation.append(
            ConversationItem(
                role=role,
                kind=observation.kind.value,
                content=observation.text[: self.runtime.max_item_chars],
                provenance_ids=list(observation.provenance_ids),
            )
        )

    def _tool_specs(self) -> list[dict[str, object]]:
        return [tool.spec() for tool in self.gateway.registry if tool.name in self.scenario.allowed_tools]

    def _request(self, step_id: int, turn_index: int, goal: str, action: CandidateAction) -> DefenseRequest:
        items = self._conversation[-self.runtime.max_conversation_items :]
        referenced = {pid for item in items for pid in item.provenance_ids}
        referenced.update(self._turn_provenance)
        records = [
            ProvenanceRecord(id=pid, provenance=self._provenance[pid])
            for pid in sorted(referenced)
            if pid in self._provenance
        ]
        seen = [self._provenance[pid] for pid in self._turn_provenance if pid in self._provenance]
        last = self._observations[-1] if self._observations else None
        return DefenseRequest(
            run_id=self.log.run_id,
            step_id=step_id,
            runtime_timestamp=self.clock.tick(),
            user_goal=goal,
            conversation=items,
            observation=ObservationView(
                kind=last.kind.value,
                content=last.text[: self.runtime.max_item_chars],
                provenance_ids=list(last.provenance_ids),
            )
            if last
            else None,
            candidate_action=action,
            policy_context=dict(self.policy_context),
            provenance=records,
            history_digest=HistoryDigest(
                steps_taken=step_id - 1,
                turn_index=turn_index,
                tool_calls=self._tool_calls[-20:],
                confirmations_granted=sorted(self.state.confirmations),
                blocked_count=self._blocked,
                escalated_count=self._escalated,
                least_trusted_seen=least_trusted([p.trust_level for p in seen]).value if seen else None,
                most_sensitive_seen=most_sensitive([p.sensitivity for p in seen]).value if seen else None,
            ),
        )

    def _decide(self, request: DefenseRequest) -> tuple[DefenseDecision, float, str | None]:
        started = time.perf_counter()
        try:
            decision = self.defense.decide(request)
            error = None
        except Exception as exc:
            decision = fail_mode_decision(self.runtime.fail_mode, f"{type(exc).__name__}: {exc}")
            error = type(exc).__name__
        latency_ms = (time.perf_counter() - started) * 1000
        return decision, latency_ms, error

    def _valid_rewrite(self, original: CandidateAction, rewritten: CandidateAction) -> bool:
        if rewritten.final and not original.final:
            return False
        if rewritten.type is ActionType.TOOL_CALL:
            return rewritten.tool in self.gateway.registry
        return True

    def _confirm(self, step_id: int, turn_index: int, target: CandidateAction) -> bool:
        approved = self.hooks.human_confirm(step_id, turn_index, target)
        if approved:
            self.state.confirmations.add(target.digest())
        if isinstance(self.defense, SentinelFirewallDefense):
            self.defense.record_human_approval(
                target,
                approved=approved,
                step_id=step_id,
                timestamp=self.clock.tick(),
            )
        self.log.append(
            EventType.HUMAN_CONFIRMATION,
            Actor.HUMAN_SIMULATOR,
            step_id,
            {"tool": target.tool, "action_digest": target.digest(), "approved": approved},
        )
        return approved

    # ---- main loop ------------------------------------------------------------------------
    def run(self) -> AgentRunResult:
        step_id = 0
        result = AgentRunResult(steps=0, termination="completed")
        for turn_index, turn in enumerate(self.scenario.turns):
            self._turn_provenance = []
            self.model.start_turn(
                turn.goal,
                TurnHints(
                    tools=self._tool_specs(),
                    reference_plan=tuple(turn.reference_plan) if self.include_reference_plan else (),
                ),
            )
            user_prov = Provenance(
                source_type=SourceType.USER,
                source_id=f"turn-{turn_index}",
                trust_level=TrustLevel.AUTHENTICATED_USER,
                origin_actor="user",
                retrieved_via="chat",
                timestamp=self.clock.tick(),
            )
            ids = self._register([user_prov])
            self.log.append(
                EventType.USER_MESSAGE,
                Actor.USER,
                step_id,
                {"turn": turn_index, "text": turn.goal},
                provenance_refs=ids,
            )
            user_obs = Observation(FeedbackKind.USER_MESSAGE, turn.goal, ids)
            self._remember("user", user_obs)
            self.model.observe(Feedback(FeedbackKind.USER_MESSAGE, user_obs))

            entries = self.memory.recall()
            if entries:
                memory_prov = [
                    Provenance(
                        source_type=SourceType.MEMORY,
                        source_id=e.entry_id,
                        trust_level=e.trust_level,
                        origin_actor="agent_memory",
                        retrieved_via="memory_recall",
                        timestamp=self.clock.tick(),
                    )
                    for e in entries
                ]
                ids = self._register(memory_prov)
                text = "\n".join(e.content for e in entries)
                self.log.append(
                    EventType.MEMORY_READ,
                    Actor.AGENT,
                    step_id,
                    {"entries": [e.entry_id for e in entries]},
                    provenance_refs=ids,
                )
                memory_obs = Observation(FeedbackKind.MEMORY, text, ids)
                self._remember("memory", memory_obs)
                self.model.observe(Feedback(FeedbackKind.MEMORY, memory_obs))

            turn_done = False
            while not turn_done:
                if step_id >= self.scenario.max_steps:
                    result.termination = "max_steps"
                    result.steps = step_id
                    return result
                self.hooks.before_step(step_id + 1, turn_index)
                context = AgentContext(
                    goal=turn.goal,
                    turn_index=turn_index,
                    step_id=step_id + 1,
                    observations=list(self._observations),
                    provenance=dict(self._provenance),
                    tools=self._tool_specs(),
                )
                try:
                    action = self.model.propose(context)
                except ModelError as exc:
                    result.termination = f"model_error: {exc}"[:200]
                    result.steps = step_id
                    return result
                step_id += 1
                turn_done = self._step(step_id, turn_index, turn.goal, action, result)
        result.steps = step_id
        return result

    def _step(self, step_id: int, turn_index: int, goal: str, action: CandidateAction, result: AgentRunResult) -> bool:
        request = self._request(step_id, turn_index, goal, action)
        decision, latency_ms, error = self._decide(request)
        self.hooks.on_decision(step_id, turn_index, action, decision, latency_ms, error)
        self.log.append(
            EventType.DEFENSE_DECISION,
            Actor.DEFENSE,
            step_id,
            {
                "action": action.model_dump(mode="json"),
                "decision": decision.decision.value,
                "risk_score": decision.risk_score,
                "confidence": decision.confidence,
                "reason_codes": decision.reason_codes,
                "explanation": decision.explanation,
                "rewritten_action": decision.rewritten_action.model_dump(mode="json")
                if decision.rewritten_action
                else None,
                "metadata": decision.metadata,
                "defense_error": error,
            },
        )

        effective: CandidateAction | None = None
        if decision.decision is Decision.ALLOW:
            effective = action
        elif decision.decision is Decision.REWRITE and decision.rewritten_action is not None:
            if self._valid_rewrite(action, decision.rewritten_action):
                effective = decision.rewritten_action
        elif decision.decision is Decision.ESCALATE:
            self._escalated += 1
            if action.type is ActionType.TOOL_CALL:
                if self._confirm(step_id, turn_index, action):
                    effective = action
            elif self.hooks.human_confirm(step_id, turn_index, action):
                effective = action

        if action.type is ActionType.TOOL_CALL and action.tool:
            self._tool_calls.append(
                ToolCallSummary(step_id=step_id, tool=action.tool, decision=decision.decision.value)
            )
        if effective is None:
            self._blocked += 1
            text = f"Action blocked by safety layer ({', '.join(decision.reason_codes) or 'no reason'})."
            obs = Observation(FeedbackKind.BLOCKED, text)
            self._remember("safety", obs)
            self.model.observe(Feedback(FeedbackKind.BLOCKED, obs, action=action, succeeded=False))
            return action.final
        return self._execute(step_id, turn_index, effective, result)

    def _execute(self, step_id: int, turn_index: int, action: CandidateAction, result: AgentRunResult) -> bool:
        if action.type is ActionType.RESPOND:
            content = action.content or ""
            self.log.append(
                EventType.MODEL_OUTPUT,
                Actor.AGENT,
                step_id,
                {"turn": turn_index, "content": content, "final": action.final},
            )
            self.hooks.on_sink(step_id, action, Sink(RESPONSE_SINK, TrustLevel.AUTHENTICATED_USER, content))
            self.hooks.on_response(step_id, turn_index, action)
            result.responses.append((turn_index, content))
            obs = Observation(FeedbackKind.RESPONSE, content)
            self._remember("agent", obs)
            self.model.observe(Feedback(FeedbackKind.RESPONSE, obs, action=action))
            return action.final

        if action.type is ActionType.MEMORY_WRITE:
            content = action.content or ""
            turn_trust = [self._provenance[p].trust_level for p in self._turn_provenance]
            taint = least_trusted(turn_trust)
            entry = self.memory.write(content, taint, step_id)
            self.log.append(
                EventType.MEMORY_WRITE,
                Actor.AGENT,
                step_id,
                {"entry_id": entry.entry_id, "content": content, "trust_level": taint.value},
            )
            self.hooks.on_sink(step_id, action, Sink(MEMORY_SINK, TrustLevel.TRUSTED_INTERNAL, content))
            obs = Observation(FeedbackKind.MEMORY_WRITTEN, f"Saved memory {entry.entry_id}.")
            self._remember("agent", obs)
            self.model.observe(Feedback(FeedbackKind.MEMORY_WRITTEN, obs, action=action))
            return False

        if action.type is ActionType.REQUEST_CONFIRMATION:
            target = action.confirmation_for
            assert target is not None
            approved = self._confirm(step_id, turn_index, target)
            text = f"Human {'approved' if approved else 'denied'} {target.tool}."
            obs = Observation(FeedbackKind.CONFIRMATION, text)
            self._remember("human", obs)
            self.model.observe(Feedback(FeedbackKind.CONFIRMATION, obs, action=action, approved=approved))
            return False

        # tool call
        confirmed = action.digest() in self.state.confirmations
        preparation = None
        executed_action = action
        if isinstance(self.defense, SentinelFirewallDefense):
            preparation = self.defense.prepare_execution(
                action,
                step_id=step_id,
                timestamp=self.clock.tick(),
            )
            executed_action = preparation.action
        tool = self.gateway.registry.get(executed_action.tool or "")
        self.log.append(
            EventType.TOOL_REQUEST,
            Actor.AGENT,
            step_id,
            {
                "tool": executed_action.tool,
                "arguments": executed_action.arguments,
                "confirmed": confirmed,
                "guarded": preparation is not None,
            },
        )
        if preparation is None or preparation.permitted:
            self.hooks.before_tool(step_id, executed_action, tool)
        gateway_result = (
            self.defense.execute_prepared(
                preparation,
                step_id=step_id,
                timestamp=self.clock.tick(),
            )
            if isinstance(self.defense, SentinelFirewallDefense) and preparation is not None
            else self.gateway.execute(executed_action, step_id, self.clock.tick())
        )
        outcome = gateway_result.outcome
        ids = self._register(outcome.provenance)
        read_only = tool is not None and tool.capabilities == frozenset({"read"})
        event_type = EventType.RETRIEVAL_RESULT if read_only and outcome.succeeded else EventType.TOOL_RESULT
        self.log.append(
            event_type,
            Actor.TOOL_GATEWAY,
            step_id,
            {
                "tool": executed_action.tool,
                "succeeded": outcome.succeeded,
                "error": outcome.error,
                "result": outcome.result,
                "effects": [name for name, _ in outcome.effects],
            },
            provenance_refs=ids,
        )
        self.hooks.after_tool(step_id, turn_index, executed_action, gateway_result, confirmed)
        if gateway_result.sink is not None:
            self.hooks.on_sink(step_id, executed_action, gateway_result.sink)
        if self._tool_calls and self._tool_calls[-1].step_id == step_id:
            last = self._tool_calls[-1]
            self._tool_calls[-1] = ToolCallSummary(
                step_id=last.step_id, tool=last.tool, decision=last.decision, succeeded=outcome.succeeded
            )
        text = json.dumps(outcome.result, ensure_ascii=False, sort_keys=True)
        obs = Observation(FeedbackKind.TOOL_RESULT, text, ids, data=outcome.result)
        self._remember("tool", obs)
        self.model.observe(Feedback(FeedbackKind.TOOL_RESULT, obs, action=executed_action, succeeded=outcome.succeeded))
        return False
