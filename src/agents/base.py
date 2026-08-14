"""
Base agent interface for the Biodefense Alerting & Response Engine.

Agents are the THINKING layer. They consume raw data and produce
BoundedSignals. They do NOT make decisions — the state machine does.

Every agent must:
  1. Produce only BoundedSignals (value and confidence in [0,1])
  2. Be deterministic given the same inputs
  3. Declare its agent_id
  4. Provide a rationale for every vote

TRACEABILITY: spec/biodefense.tla :: Agent
"""

from __future__ import annotations

import abc
from typing import List, Sequence

from ..types import AgentVote, AlertLevel, BoundedSignal


class BaseAgent(abc.ABC):
    """Abstract base for all agents in the system."""

    def __init__(self, agent_id: str):
        if not agent_id:
            raise ValueError("agent_id must be non-empty")
        self._agent_id = agent_id

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @abc.abstractmethod
    def analyze(self, data: dict) -> List[BoundedSignal]:
        """
        Analyze raw data and produce bounded signals.

        This is the THINKING step. The output is constrained:
        - All signals must have value in [0.0, 1.0]
        - All signals must have confidence in [0.0, 1.0]
        - All signals must reference this agent's agent_id

        Args:
            data: Raw input data (format depends on agent type)

        Returns:
            List of BoundedSignals
        """
        ...

    @abc.abstractmethod
    def vote(self, signals: Sequence[BoundedSignal]) -> AgentVote:
        """
        Given accumulated signals, cast a vote on the appropriate alert level.

        This is still THINKING — the vote is input to the state machine,
        not a decision.

        Args:
            signals: All currently pending signals from all agents

        Returns:
            An AgentVote expressing this agent's assessment
        """
        ...

    def _make_signal(
        self,
        signal_type: str,
        value: float,
        confidence: float,
        timestamp: int,
        evidence_ids: frozenset = frozenset(),
    ) -> BoundedSignal:
        """Helper to create a signal with bounds enforcement."""
        # Clamp to bounds — but log if clamping was needed
        clamped_value = max(0.0, min(1.0, value))
        clamped_confidence = max(0.0, min(1.0, confidence))

        return BoundedSignal(
            source_agent=self._agent_id,
            signal_type=signal_type,
            value=clamped_value,
            confidence=clamped_confidence,
            timestamp_monotonic=timestamp,
            evidence_ids=evidence_ids,
        )
