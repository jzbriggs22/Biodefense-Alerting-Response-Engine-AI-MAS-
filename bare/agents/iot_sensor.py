"""
IoT / Sensor Stream Agent

Ingests anonymized data from:
    - Wastewater pathogen monitoring
    - Hospital syndromic surveillance feeds
    - EMS call volume metadata
    - Wearable aggregate health metrics

Anomaly detection approach:
    1. Seasonal decomposition: removes expected periodic patterns
       (day-of-week, seasonal trends) using exponential moving averages.
    2. Statistical deviation: flags readings that exceed a configurable
       number of standard deviations from the de-seasonalized baseline.
    3. Correlation gating: requires anomalies to persist across
       multiple consecutive readings before reporting (reduces
       single-point false positives).

All data is anonymized at the source boundary. This agent never
receives or stores PII.
"""

from __future__ import annotations

import asyncio
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from bare.core.base_agent import BaseAgent
from bare.core.message_bus import MessageBus, Topics
from bare.schemas.events import (
    AgentRole,
    AnomalyReport,
    RawSignal,
    SignalSource,
)


# ---------------------------------------------------------------------------
# Seasonality-aware tracker
# ---------------------------------------------------------------------------

SENSOR_SOURCES = {
    SignalSource.WASTEWATER,
    SignalSource.SYNDROMIC,
    SignalSource.EMS_METADATA,
    SignalSource.WEARABLE_AGGREGATE,
}


@dataclass
class SensorBaseline:
    """Exponentially-weighted moving average with seasonal adjustment.

    Parameters:
        alpha: smoothing factor for the EMA (0 < alpha <= 1).
               Lower values give more weight to history.
        window_size: number of readings retained for std deviation.
        seasonal_period: expected periodicity (e.g. 7 for weekly).
    """
    alpha: float = 0.1
    window_size: int = 168        # ~1 week of hourly readings
    seasonal_period: int = 24     # hourly data, daily seasonality
    _ema: float | None = None
    _readings: deque[float] = field(default_factory=lambda: deque(maxlen=168))
    _seasonal_offsets: dict[int, float] = field(default_factory=dict)

    @property
    def mean(self) -> float:
        if self._ema is None:
            return 0.0
        return self._ema

    @property
    def std(self) -> float:
        if len(self._readings) < 2:
            return 1.0
        m = sum(self._readings) / len(self._readings)
        var = sum((x - m) ** 2 for x in self._readings) / (len(self._readings) - 1)
        return max(math.sqrt(var), 0.01)

    def update(self, value: float, slot: int = 0) -> float:
        """Update baseline and return the de-seasonalized value."""
        # Seasonal adjustment
        seasonal = self._seasonal_offsets.get(slot % self.seasonal_period, 0.0)
        adjusted = value - seasonal

        # Update EMA
        if self._ema is None:
            self._ema = adjusted
        else:
            self._ema = self.alpha * adjusted + (1 - self.alpha) * self._ema

        self._readings.append(adjusted)

        # Update seasonal offset with slow learning
        residual = value - (self._ema + seasonal)
        self._seasonal_offsets[slot % self.seasonal_period] = seasonal + 0.05 * residual

        return adjusted


# ---------------------------------------------------------------------------
# Agent implementation
# ---------------------------------------------------------------------------

class IoTSensorAgent(BaseAgent):
    """Processes sensor streams and detects statistical anomalies."""

    def __init__(
        self,
        bus: MessageBus,
        z_threshold: float = 3.0,
        persistence_required: int = 2,
        agent_id: str = "iot_sensor_01",
    ) -> None:
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.IOT_SENSOR,
            bus=bus,
            cycle_interval=0.5,
        )
        self.z_threshold = z_threshold
        self.persistence_required = persistence_required
        self._input_queue: asyncio.Queue[Any] | None = None

        # Baseline per (region, source, pathogen_hint)
        self._baselines: dict[tuple[str, str, str], SensorBaseline] = defaultdict(
            SensorBaseline
        )
        # Consecutive anomaly counter per key
        self._anomaly_streak: dict[tuple[str, str, str], int] = defaultdict(int)
        self._cycle_slot: int = 0

    async def start(self) -> None:
        self._input_queue = await self.bus.subscribe(
            Topics.RAW_SIGNALS, self.agent_id
        )
        await super().start()

    async def _run_cycle(self) -> None:
        if self._input_queue is None:
            return

        batch: list[RawSignal] = []
        try:
            while True:
                signal = self._input_queue.get_nowait()
                if isinstance(signal, RawSignal) and signal.source in SENSOR_SOURCES:
                    batch.append(signal)
        except asyncio.QueueEmpty:
            pass

        for signal in batch:
            key = (
                signal.region or "global",
                signal.source.value,
                signal.pathogen_hint or "general",
            )
            baseline = self._baselines[key]
            adjusted = baseline.update(signal.raw_score, self._cycle_slot)
            z = (adjusted - baseline.mean) / baseline.std

            if z >= self.z_threshold:
                self._anomaly_streak[key] += 1
            else:
                self._anomaly_streak[key] = 0

            if self._anomaly_streak[key] >= self.persistence_required:
                report = AnomalyReport(
                    originating_agent=AgentRole.IOT_SENSOR,
                    region=key[0],
                    pathogen_hint=key[2],
                    anomaly_score=min(1.0, z / 5.0),
                    baseline_value=baseline.mean,
                    observed_value=signal.raw_score,
                    z_score=z,
                    contributing_signals=(signal.signal_id,),
                    explanation=(
                        f"Sensor '{key[1]}' in '{key[0]}' reading {signal.raw_score:.3f} "
                        f"is {z:.2f}σ above baseline (mean={baseline.mean:.3f}) "
                        f"for {self._anomaly_streak[key]} consecutive readings"
                    ),
                )
                await self.bus.publish(Topics.ANOMALY_REPORTS, report)
                self.logger.info(
                    "Sensor anomaly: %s/%s in %s (z=%.2f, streak=%d)",
                    key[1], key[2], key[0], z, self._anomaly_streak[key],
                )
                # Reset streak after reporting to avoid duplicate alerts
                self._anomaly_streak[key] = 0

        self._cycle_slot += 1
