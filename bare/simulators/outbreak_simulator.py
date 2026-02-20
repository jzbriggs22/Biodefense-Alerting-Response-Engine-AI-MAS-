"""
Simulated data generators for testing the BARE system.

Provides realistic synthetic data for:
    1. OSINT text signals (news articles, bulletins)
    2. Sensor readings (wastewater, syndromic, EMS, wearable)
    3. Configurable outbreak scenarios

These generators produce data that exercises the full agent pipeline
without requiring external API access or real data.

Scenarios are designed to test:
    - True positive detection (real outbreaks)
    - False positive resistance (noise-only periods)
    - Multi-region correlation (simultaneous events)
    - Gradual emergence vs sudden onset
    - Single-source vs multi-source corroboration
"""

from __future__ import annotations

import asyncio
import math
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from bare.core.message_bus import MessageBus, Topics
from bare.schemas.events import RawSignal, SignalSource


class ScenarioType(Enum):
    """Predefined outbreak scenarios."""
    BASELINE_NOISE = "baseline_noise"
    NATURAL_GRADUAL = "natural_gradual"
    NATURAL_SUDDEN = "natural_sudden"
    MULTI_REGION_SIMULTANEOUS = "multi_region_simultaneous"
    HOSTILE_RELEASE = "hostile_release"
    FALSE_ALARM_SEASONAL = "false_alarm_seasonal"


@dataclass
class ScenarioConfig:
    """Configuration for a simulated scenario."""
    scenario_type: ScenarioType = ScenarioType.BASELINE_NOISE
    pathogen: str = "influenza_h5n1"
    regions: tuple[str, ...] = ("US-NY",)
    duration_cycles: int = 100
    onset_cycle: int = 30          # When the outbreak signal begins
    peak_cycle: int = 60           # When the outbreak signal peaks
    baseline_rate: float = 0.1     # Normal background signal level
    peak_rate: float = 0.9         # Peak outbreak signal level
    noise_std: float = 0.05        # Gaussian noise standard deviation
    sensor_sources: tuple[SignalSource, ...] = (
        SignalSource.WASTEWATER,
        SignalSource.SYNDROMIC,
    )
    osint_sources: tuple[SignalSource, ...] = (
        SignalSource.NEWS,
        SignalSource.WHO_BULLETIN,
    )


# ---------------------------------------------------------------------------
# Scenario library
# ---------------------------------------------------------------------------

SCENARIOS: dict[ScenarioType, ScenarioConfig] = {
    ScenarioType.BASELINE_NOISE: ScenarioConfig(
        scenario_type=ScenarioType.BASELINE_NOISE,
        pathogen="influenza_seasonal",
        regions=("US-NY",),
        duration_cycles=80,
        onset_cycle=999,       # Never triggers
        peak_cycle=999,
        baseline_rate=0.1,
        peak_rate=0.1,
        noise_std=0.03,
    ),
    ScenarioType.NATURAL_GRADUAL: ScenarioConfig(
        scenario_type=ScenarioType.NATURAL_GRADUAL,
        pathogen="cholera",
        regions=("BD-DA",),    # Dhaka, Bangladesh
        duration_cycles=100,
        onset_cycle=25,
        peak_cycle=70,
        baseline_rate=0.08,
        peak_rate=0.75,
        noise_std=0.04,
    ),
    ScenarioType.NATURAL_SUDDEN: ScenarioConfig(
        scenario_type=ScenarioType.NATURAL_SUDDEN,
        pathogen="ebola",
        regions=("CD-KN",),    # Kinshasa, DRC
        duration_cycles=80,
        onset_cycle=20,
        peak_cycle=30,
        baseline_rate=0.05,
        peak_rate=0.85,
        noise_std=0.03,
    ),
    ScenarioType.MULTI_REGION_SIMULTANEOUS: ScenarioConfig(
        scenario_type=ScenarioType.MULTI_REGION_SIMULTANEOUS,
        pathogen="novel_respiratory",
        regions=("US-NY", "US-CA", "US-TX"),
        duration_cycles=80,
        onset_cycle=20,
        peak_cycle=40,
        baseline_rate=0.06,
        peak_rate=0.8,
        noise_std=0.04,
    ),
    ScenarioType.HOSTILE_RELEASE: ScenarioConfig(
        scenario_type=ScenarioType.HOSTILE_RELEASE,
        pathogen="anthrax",
        regions=("US-DC", "US-NY"),
        duration_cycles=60,
        onset_cycle=10,
        peak_cycle=15,
        baseline_rate=0.02,
        peak_rate=0.95,
        noise_std=0.02,
        sensor_sources=(
            SignalSource.SYNDROMIC,
            SignalSource.EMS_METADATA,
            SignalSource.WEARABLE_AGGREGATE,
        ),
    ),
    ScenarioType.FALSE_ALARM_SEASONAL: ScenarioConfig(
        scenario_type=ScenarioType.FALSE_ALARM_SEASONAL,
        pathogen="influenza_seasonal",
        regions=("US-IL",),
        duration_cycles=100,
        onset_cycle=30,
        peak_cycle=50,
        baseline_rate=0.1,
        peak_rate=0.35,   # Below typical detection threshold
        noise_std=0.08,   # High noise
    ),
}


# ---------------------------------------------------------------------------
# Signal generators
# ---------------------------------------------------------------------------

def _outbreak_envelope(
    cycle: int,
    onset: int,
    peak: int,
    baseline: float,
    peak_rate: float,
) -> float:
    """Compute the signal envelope for a given cycle.

    Uses a logistic growth curve for onset and gaussian decay after peak.
    """
    if cycle < onset:
        return baseline
    if cycle <= peak:
        # Logistic growth from baseline to peak_rate
        progress = (cycle - onset) / max(1, peak - onset)
        # Sigmoid: output in [0, 1], mapped to [baseline, peak_rate]
        x = 10 * (progress - 0.5)  # Center sigmoid at midpoint
        sigmoid = 1.0 / (1.0 + math.exp(-x))
        return baseline + (peak_rate - baseline) * sigmoid
    else:
        # Exponential decay after peak
        decay = math.exp(-0.05 * (cycle - peak))
        return baseline + (peak_rate - baseline) * decay


def generate_signal(
    config: ScenarioConfig,
    cycle: int,
    source: SignalSource,
    region: str,
    rng: random.Random | None = None,
) -> RawSignal:
    """Generate a single synthetic signal for the given cycle."""
    if rng is None:
        rng = random.Random()

    envelope = _outbreak_envelope(
        cycle, config.onset_cycle, config.peak_cycle,
        config.baseline_rate, config.peak_rate,
    )

    # Add noise
    noise = rng.gauss(0, config.noise_std)
    value = max(0.0, min(1.0, envelope + noise))

    # Generate keyword hints for OSINT sources
    keyword_hits: tuple[str, ...] = ()
    if source in (SignalSource.NEWS, SignalSource.WHO_BULLETIN,
                  SignalSource.CDC_BULLETIN, SignalSource.PREPRINT):
        if value > 0.3:
            keyword_hits = (config.pathogen, "outbreak")
        if value > 0.6:
            keyword_hits = (config.pathogen, "outbreak", "cluster of illness")

    return RawSignal(
        source=source,
        source_ref=f"sim_{config.scenario_type.value}_{cycle}",
        region=region,
        pathogen_hint=config.pathogen,
        keyword_hits=keyword_hits,
        raw_score=value,
        metadata={
            "scenario": config.scenario_type.value,
            "cycle": cycle,
            "envelope": envelope,
        },
    )


# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------

class ScenarioRunner:
    """Runs a complete scenario, publishing signals to the message bus."""

    def __init__(
        self,
        bus: MessageBus,
        config: ScenarioConfig | None = None,
        scenario_type: ScenarioType = ScenarioType.NATURAL_GRADUAL,
        seed: int = 42,
    ) -> None:
        self.bus = bus
        self.config = config or SCENARIOS[scenario_type]
        self.rng = random.Random(seed)
        self._cycle = 0

    async def run(self, inter_cycle_delay: float = 0.1) -> dict[str, Any]:
        """Run the full scenario, returning summary statistics."""
        signals_published = 0

        for cycle in range(self.config.duration_cycles):
            self._cycle = cycle

            # Generate signals from each source × region
            all_sources = list(self.config.sensor_sources) + list(self.config.osint_sources)
            for region in self.config.regions:
                for source in all_sources:
                    signal = generate_signal(
                        self.config, cycle, source, region, self.rng,
                    )
                    await self.bus.publish(Topics.RAW_SIGNALS, signal)
                    signals_published += 1

            await asyncio.sleep(inter_cycle_delay)

        return {
            "scenario": self.config.scenario_type.value,
            "pathogen": self.config.pathogen,
            "regions": self.config.regions,
            "total_cycles": self.config.duration_cycles,
            "signals_published": signals_published,
        }

    async def run_single_cycle(self) -> int:
        """Run a single cycle and return number of signals published."""
        signals_published = 0
        all_sources = list(self.config.sensor_sources) + list(self.config.osint_sources)
        for region in self.config.regions:
            for source in all_sources:
                signal = generate_signal(
                    self.config, self._cycle, source, region, self.rng,
                )
                await self.bus.publish(Topics.RAW_SIGNALS, signal)
                signals_published += 1
        self._cycle += 1
        return signals_published
