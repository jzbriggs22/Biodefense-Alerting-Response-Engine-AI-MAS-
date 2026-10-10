"""
Epidemiological analysis agent.

Consumes structured epidemiological data (case counts, syndromic
surveillance, laboratory confirmations) and produces bounded signals.

This is the highest-confidence agent in the system because it operates
on laboratory-confirmed data. It is also the slowest — epi data arrives
hours to days after an event.

TRACEABILITY: spec/biodefense.tla :: EpiAgent
"""

from __future__ import annotations

from typing import List, Sequence

from ..types import AgentVote, AlertLevel, BoundedSignal
from .base import BaseAgent

# Epi data can reach high confidence — it includes lab confirmation
EPI_MAX_CONFIDENCE = 0.95


class EpidemiologicalAgent(BaseAgent):
    """Agent that analyzes epidemiological surveillance data."""

    def __init__(self):
        super().__init__(agent_id="epi_analyst")

    def analyze(self, data: dict) -> List[BoundedSignal]:
        """
        Analyze epidemiological data and produce signals.

        Expected data format:
        {
            "indicators": [
                {
                    "indicator_type": str,
                    "normalized_severity": float (0-1),
                    "lab_confirmed": bool,
                    "sample_size": int,
                    "timestamp": int,
                    "evidence_id": str,
                }
            ]
        }
        """
        signals = []
        indicators = data.get("indicators", [])

        for indicator in indicators:
            severity = indicator.get("normalized_severity", 0.0)
            lab_confirmed = indicator.get("lab_confirmed", False)
            sample_size = indicator.get("sample_size", 0)

            # Confidence based on lab confirmation and sample size
            if lab_confirmed:
                base_confidence = 0.8
            else:
                base_confidence = 0.4

            # Adjust for sample size (diminishing returns)
            sample_bonus = min(0.15, sample_size * 0.01) if sample_size > 0 else 0
            confidence = min(base_confidence + sample_bonus, EPI_MAX_CONFIDENCE)

            signal = self._make_signal(
                signal_type=f"epi:{indicator.get('indicator_type', 'unknown')}",
                value=severity,
                confidence=confidence,
                timestamp=indicator.get("timestamp", 0),
                evidence_ids=frozenset(
                    [indicator["evidence_id"]] if "evidence_id" in indicator else []
                ),
            )
            signals.append(signal)

        return signals

    def vote(self, signals: Sequence[BoundedSignal]) -> AgentVote:
        """
        Cast a vote based on epidemiological signals.

        Epi data is the only agent type that can support CONFIRMED level,
        because it includes laboratory confirmation.
        """
        my_signals = [s for s in signals if s.source_agent == self._agent_id]

        if not my_signals:
            return AgentVote(
                agent_id=self._agent_id,
                proposed_level=AlertLevel.NORMAL,
                signal_ids=(),
                confidence=0.0,
                rationale="No epidemiological signals present",
            )

        max_value = max(s.value for s in my_signals)
        max_confidence = max(s.confidence for s in my_signals)
        mean_confidence = sum(s.confidence for s in my_signals) / len(my_signals)

        # Epi agent can propose all levels including CONFIRMED
        if max_value >= 0.8 and max_confidence >= 0.75:
            proposed = AlertLevel.CONFIRMED
        elif max_value >= 0.6:
            proposed = AlertLevel.SUSPECTED
        elif max_value >= 0.35:
            proposed = AlertLevel.ELEVATED
        else:
            proposed = AlertLevel.NORMAL

        return AgentVote(
            agent_id=self._agent_id,
            proposed_level=proposed,
            signal_ids=tuple(s.signal_id for s in my_signals),
            confidence=min(mean_confidence, EPI_MAX_CONFIDENCE),
            rationale=(
                f"Epi: {len(my_signals)} indicators, "
                f"max severity={max_value:.2f}, "
                f"max confidence={max_confidence:.2f}"
            ),
        )
