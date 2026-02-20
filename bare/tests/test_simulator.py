"""Tests for the outbreak simulator."""

import asyncio
import pytest
from bare.core.message_bus import MessageBus, Topics
from bare.simulators.outbreak_simulator import (
    ScenarioConfig,
    ScenarioRunner,
    ScenarioType,
    SCENARIOS,
    _outbreak_envelope,
    generate_signal,
)
from bare.schemas.events import SignalSource


class TestOutbreakEnvelope:
    def test_baseline_before_onset(self):
        val = _outbreak_envelope(cycle=5, onset=20, peak=60, baseline=0.1, peak_rate=0.9)
        assert val == pytest.approx(0.1)

    def test_increases_after_onset(self):
        pre = _outbreak_envelope(cycle=19, onset=20, peak=60, baseline=0.1, peak_rate=0.9)
        post = _outbreak_envelope(cycle=40, onset=20, peak=60, baseline=0.1, peak_rate=0.9)
        assert post > pre

    def test_peak_near_max(self):
        val = _outbreak_envelope(cycle=60, onset=20, peak=60, baseline=0.1, peak_rate=0.9)
        assert val > 0.8

    def test_decay_after_peak(self):
        at_peak = _outbreak_envelope(cycle=60, onset=20, peak=60, baseline=0.1, peak_rate=0.9)
        after = _outbreak_envelope(cycle=100, onset=20, peak=60, baseline=0.1, peak_rate=0.9)
        assert after < at_peak


class TestSignalGeneration:
    def test_generates_valid_signal(self):
        config = SCENARIOS[ScenarioType.NATURAL_GRADUAL]
        signal = generate_signal(config, 50, SignalSource.WASTEWATER, "US-NY")
        assert 0.0 <= signal.raw_score <= 1.0
        assert signal.source == SignalSource.WASTEWATER
        assert signal.region == "US-NY"

    def test_reproducible_with_seed(self):
        import random
        config = SCENARIOS[ScenarioType.NATURAL_GRADUAL]
        rng1 = random.Random(42)
        rng2 = random.Random(42)
        s1 = generate_signal(config, 50, SignalSource.NEWS, "US-NY", rng1)
        s2 = generate_signal(config, 50, SignalSource.NEWS, "US-NY", rng2)
        assert s1.raw_score == s2.raw_score


class TestScenarioRunner:
    @pytest.mark.asyncio
    async def test_baseline_noise_run(self):
        bus = MessageBus()
        q = await bus.subscribe(Topics.RAW_SIGNALS, "test")
        runner = ScenarioRunner(
            bus=bus,
            scenario_type=ScenarioType.BASELINE_NOISE,
            seed=42,
        )
        # Run just a few cycles
        runner.config = ScenarioConfig(
            scenario_type=ScenarioType.BASELINE_NOISE,
            duration_cycles=5,
            onset_cycle=999,
            peak_cycle=999,
            baseline_rate=0.1,
            peak_rate=0.1,
            noise_std=0.03,
            sensor_sources=(SignalSource.WASTEWATER,),
            osint_sources=(SignalSource.NEWS,),
            regions=("US-NY",),
        )
        results = await runner.run(inter_cycle_delay=0.01)
        assert results["signals_published"] == 10  # 5 cycles × 2 sources × 1 region

    @pytest.mark.asyncio
    async def test_all_scenarios_defined(self):
        """Every ScenarioType must have a config in SCENARIOS."""
        for st in ScenarioType:
            assert st in SCENARIOS
