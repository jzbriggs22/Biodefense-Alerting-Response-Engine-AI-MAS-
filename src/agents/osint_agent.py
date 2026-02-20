"""
OSINT (Open Source Intelligence) monitoring agent.

Consumes structured reports from OSINT feeds and produces bounded
signals indicating potential biodefense threats.

This agent is particularly susceptible to adversarial manipulation
because its inputs come from public sources. The confidence values
MUST reflect this inherent unreliability.

TRACEABILITY: spec/biodefense.tla :: OSINTAgent
"""

from __future__ import annotations

from typing import List, Sequence

from ..types import AgentVote, AlertLevel, BoundedSignal
from .base import BaseAgent


# Maximum confidence for OSINT data — OSINT is inherently unverified
OSINT_MAX_CONFIDENCE = 0.6


class OSINTAgent(BaseAgent):
    """Agent that monitors open-source intelligence feeds."""

    def __init__(self):
        super().__init__(agent_id="osint_monitor")

    def analyze(self, data: dict) -> List[BoundedSignal]:
        """
        Analyze OSINT data and produce signals.

        Expected data format:
        {
            "reports": [
                {
                    "source": str,
                    "threat_type": str,
                    "severity_score": float (0-1),
                    "corroboration_count": int,
                    "timestamp": int,
                    "evidence_id": str,
                }
            ]
        }
        """
        signals = []
        reports = data.get("reports", [])

        for report in reports:
            severity = report.get("severity_score", 0.0)
            corroboration = report.get("corroboration_count", 0)

            # Confidence scales with corroboration but is capped
            # Single-source OSINT: very low confidence
            # Multi-source: higher but still capped
            raw_confidence = min(
                0.2 + (corroboration * 0.1),
                OSINT_MAX_CONFIDENCE,
            )

            signal = self._make_signal(
                signal_type=f"osint:{report.get('threat_type', 'unknown')}",
                value=severity,
                confidence=raw_confidence,
                timestamp=report.get("timestamp", 0),
                evidence_ids=frozenset(
                    [report["evidence_id"]] if "evidence_id" in report else []
                ),
            )
            signals.append(signal)

        return signals

    def vote(self, signals: Sequence[BoundedSignal]) -> AgentVote:
        """
        Cast a vote based on OSINT signals.

        OSINT alone should never drive escalation above ELEVATED
        because it is inherently unverified.
        """
        my_signals = [s for s in signals if s.source_agent == self._agent_id]

        if not my_signals:
            return AgentVote(
                agent_id=self._agent_id,
                proposed_level=AlertLevel.NORMAL,
                signal_ids=(),
                confidence=0.0,
                rationale="No OSINT signals present",
            )

        max_value = max(s.value for s in my_signals)
        mean_confidence = sum(s.confidence for s in my_signals) / len(my_signals)

        # OSINT caps its proposed level at ELEVATED
        if max_value >= 0.5:
            proposed = AlertLevel.ELEVATED
        else:
            proposed = AlertLevel.NORMAL

        return AgentVote(
            agent_id=self._agent_id,
            proposed_level=proposed,
            signal_ids=tuple(s.signal_id for s in my_signals),
            confidence=min(mean_confidence, OSINT_MAX_CONFIDENCE),
            rationale=(
                f"OSINT: {len(my_signals)} reports, "
                f"max severity={max_value:.2f}, "
                f"mean confidence={mean_confidence:.2f}"
            ),
        )
