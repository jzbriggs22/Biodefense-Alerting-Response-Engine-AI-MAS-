"""
Main orchestration engine for the Biodefense Alerting & Response Engine.

This module wires together:
  - Agents (thinking layer)
  - State machine (deciding layer)
  - Invariant monitors (verification layer)

It is the outermost boundary of the system. All inputs enter here.
All outputs leave here. There is no other path.

TRACEABILITY: spec/biodefense.tla :: Engine
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .agents.base import BaseAgent
from .invariants import check_all_snapshot_invariants, InvariantResult
from .state_machine import (
    BiodefenseStateMachine,
    Event,
    EVENT_SIGNALS_RECEIVED,
    EVENT_VOTE_COMPLETE,
    EVENT_SAFE_MODE_ENTER,
    EVENT_SAFE_MODE_EXIT,
    EVENT_HUMAN_OVERRIDE,
    EVENT_TICK,
    TransitionThresholds,
)
from .types import (
    AgentVote,
    AlertLevel,
    BoundedSignal,
    HumanAuthorityPolicy,
    SystemSnapshot,
    TemporalConfig,
    TransitionRecord,
)


@dataclass
class EngineConfig:
    """Configuration for the biodefense engine."""
    thresholds: TransitionThresholds = field(
        default_factory=TransitionThresholds
    )
    authority_policy: HumanAuthorityPolicy = field(
        default_factory=HumanAuthorityPolicy
    )
    temporal_config: TemporalConfig = field(
        default_factory=TemporalConfig
    )
    enable_runtime_invariant_checks: bool = True


class BiodefenseEngine:
    """
    Top-level orchestrator for the biodefense alerting system.

    Lifecycle:
      1. Register agents
      2. Feed data through ingest()
      3. Call evaluate() to trigger voting and potential transitions
      4. Read state via snapshot property
      5. Review transition_log for audit trail

    TRACEABILITY: spec/biodefense.tla :: Engine
    """

    def __init__(self, config: EngineConfig = EngineConfig()):
        self._config = config
        self._fsm = BiodefenseStateMachine(
            thresholds=config.thresholds,
            authority_policy=config.authority_policy,
            temporal_config=config.temporal_config,
        )
        self._agents: Dict[str, BaseAgent] = {}
        self._all_signals: List[BoundedSignal] = []
        self._runtime_violations: List[InvariantResult] = []

    # -- Agent management --

    def register_agent(self, agent: BaseAgent) -> None:
        """Register an agent with the engine."""
        if agent.agent_id in self._agents:
            raise ValueError(f"Agent {agent.agent_id} already registered")
        self._agents[agent.agent_id] = agent

    @property
    def registered_agents(self) -> Tuple[str, ...]:
        return tuple(self._agents.keys())

    # -- Data ingestion --

    def ingest(self, agent_id: str, data: dict) -> List[BoundedSignal]:
        """
        Feed data to a specific agent and collect its signals.

        This is the THINKING step — the agent analyzes data and produces
        bounded signals. No state transition happens here.

        Returns the signals produced by the agent.
        """
        if agent_id not in self._agents:
            raise ValueError(f"Unknown agent: {agent_id}")

        agent = self._agents[agent_id]
        signals = agent.analyze(data)

        # Validate all signals before accepting
        for sig in signals:
            if sig.source_agent != agent_id:
                raise ValueError(
                    f"Agent {agent_id} produced signal claiming to be from "
                    f"{sig.source_agent}"
                )

        self._all_signals.extend(signals)

        # Feed signals to state machine
        if signals:
            event = Event(
                event_type=EVENT_SIGNALS_RECEIVED,
                signals=tuple(signals),
            )
            self._fsm.process_event(event)

        self._check_snapshot_invariants()
        return signals

    # -- Evaluation --

    def evaluate(self) -> SystemSnapshot:
        """
        Trigger agent voting and potential state transition.

        This is the DECIDING step — agents vote, votes are tallied,
        and the state machine determines if a transition is warranted.
        """
        if not self._agents:
            return self._fsm.snapshot

        # Collect votes from all agents
        votes: List[AgentVote] = []
        for agent_id, agent in self._agents.items():
            vote = agent.vote(self._all_signals)
            votes.append(vote)

        # Submit votes to state machine
        event = Event(
            event_type=EVENT_VOTE_COMPLETE,
            votes=tuple(votes),
        )
        snapshot = self._fsm.process_event(event)

        self._check_snapshot_invariants()
        return snapshot

    # -- Governance actions --

    def enter_safe_mode(self) -> SystemSnapshot:
        """Activate safe mode — disables automated escalation."""
        event = Event(event_type=EVENT_SAFE_MODE_ENTER)
        snapshot = self._fsm.process_event(event)
        self._check_snapshot_invariants()
        return snapshot

    def exit_safe_mode(self) -> SystemSnapshot:
        """Deactivate safe mode — returns to NORMAL."""
        event = Event(event_type=EVENT_SAFE_MODE_EXIT)
        snapshot = self._fsm.process_event(event)
        self._check_snapshot_invariants()
        return snapshot

    def human_override(
        self,
        operator_id: str,
        proposed_level: AlertLevel,
        rationale: str,
    ) -> SystemSnapshot:
        """
        Apply a human override to the system state.

        Human overrides bypass quorum requirements but still require
        explanation and are fully logged.
        """
        vote = AgentVote(
            agent_id=f"human:{operator_id}",
            proposed_level=proposed_level,
            signal_ids=tuple(s.signal_id for s in self._all_signals[-3:]),
            confidence=1.0,
            rationale=rationale,
        )
        event = Event(
            event_type=EVENT_HUMAN_OVERRIDE,
            votes=(vote,),
            human_override=True,
        )
        snapshot = self._fsm.process_event(event)
        self._check_snapshot_invariants()
        return snapshot

    def tick(self) -> SystemSnapshot:
        """Periodic re-evaluation."""
        event = Event(event_type=EVENT_TICK)
        snapshot = self._fsm.process_event(event)
        self._check_snapshot_invariants()
        return snapshot

    # -- Observability --

    @property
    def snapshot(self) -> SystemSnapshot:
        return self._fsm.snapshot

    @property
    def transition_log(self) -> Tuple[TransitionRecord, ...]:
        return self._fsm.transition_log

    @property
    def invariant_violations(self) -> Tuple[InvariantResult, ...]:
        return (
            self._fsm.invariant_violations
            + tuple(self._runtime_violations)
        )

    @property
    def all_signals(self) -> Tuple[BoundedSignal, ...]:
        return tuple(self._all_signals)

    # -- Internal --

    def _check_snapshot_invariants(self) -> None:
        """Check snapshot-level invariants if enabled."""
        if not self._config.enable_runtime_invariant_checks:
            return

        results = check_all_snapshot_invariants(self._fsm.snapshot)
        violations = [r for r in results if not r.holds]
        self._runtime_violations.extend(violations)
