"""
Sensor data monitoring agent.

Consumes structured data from physical/biological sensors (e.g.,
BioWatch, environmental monitors) and produces bounded signals.

Sensor data is more trustworthy than OSINT but subject to drift,
calibration errors, and adversarial spoofing.

TRACEABILITY: spec/biodefense.tla :: SensorAgent
"""

from __future__ import annotations

from typing import List, Sequence

from ..types import AgentVote, AlertLevel, BoundedSignal
from .base import BaseAgent

# Maximum confidence for sensor data
SENSOR_MAX_CONFIDENCE = 0.85


class SensorAgent(BaseAgent):
    """Agent that monitors physical/biological sensor feeds."""

    def __init__(self):
        super().__init__(agent_id="sensor_monitor")

    def analyze(self, data: dict) -> List[BoundedSignal]:
        """
        Analyze sensor data and produce signals.

        Expected data format:
        {
            "readings": [
                {
                    "sensor_id": str,
                    "reading_type": str,
                    "normalized_value": float (0-1),
                    "calibration_confidence": float (0-1),
                    "timestamp": int,
                    "evidence_id": str,
                }
            ]
        }
        """
        signals = []
        readings = data.get("readings", [])

        for reading in readings:
            value = reading.get("normalized_value", 0.0)
            calibration = reading.get("calibration_confidence", 0.5)

            # Confidence combines sensor calibration quality with
            # the inherent limits of the sensor type
            confidence = min(calibration, SENSOR_MAX_CONFIDENCE)

            signal = self._make_signal(
                signal_type=f"sensor:{reading.get('reading_type', 'unknown')}",
                value=value,
                confidence=confidence,
                timestamp=reading.get("timestamp", 0),
                evidence_ids=frozenset(
                    [reading["evidence_id"]] if "evidence_id" in reading else []
                ),
            )
            signals.append(signal)

        return signals

    def vote(self, signals: Sequence[BoundedSignal]) -> AgentVote:
        """
        Cast a vote based on sensor signals.

        Sensor data can support escalation to SUSPECTED but not
        CONFIRMED — that requires epidemiological corroboration.
        """
        my_signals = [s for s in signals if s.source_agent == self._agent_id]

        if not my_signals:
            return AgentVote(
                agent_id=self._agent_id,
                proposed_level=AlertLevel.NORMAL,
                signal_ids=(),
                confidence=0.0,
                rationale="No sensor signals present",
            )

        max_value = max(s.value for s in my_signals)
        mean_confidence = sum(s.confidence for s in my_signals) / len(my_signals)

        if max_value >= 0.7:
            proposed = AlertLevel.SUSPECTED
        elif max_value >= 0.4:
            proposed = AlertLevel.ELEVATED
        else:
            proposed = AlertLevel.NORMAL

        return AgentVote(
            agent_id=self._agent_id,
            proposed_level=proposed,
            signal_ids=tuple(s.signal_id for s in my_signals),
            confidence=min(mean_confidence, SENSOR_MAX_CONFIDENCE),
            rationale=(
                f"Sensor: {len(my_signals)} readings, "
                f"max value={max_value:.2f}, "
                f"mean confidence={mean_confidence:.2f}"
            ),
        )
