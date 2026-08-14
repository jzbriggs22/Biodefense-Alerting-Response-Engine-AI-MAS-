"""
Tests for the adversarial simulator.

Verifies that all adversarial scenarios run without invariant violations
and that the system behaves as expected under adversarial conditions.
"""

import pytest
from adversarial.scenarios import (
    generate_osint_manipulation,
    generate_sensor_drift,
    generate_correlated_noise,
    generate_total_data_loss,
    generate_conflicting_signals,
    generate_time_reorder,
    generate_human_delay,
    generate_gradual_escalation_attack,
    generate_all_scenarios,
)
from adversarial.simulator import AdversarialSimulator


class TestAdversarialScenarios:
    """Test that all scenario generators produce valid scenarios."""

    def test_all_scenarios_generate(self):
        scenarios = generate_all_scenarios(base_seed=42)
        assert len(scenarios) == 8
        for s in scenarios:
            assert s.scenario_id
            assert s.description
            assert s.steps
            assert s.expected_system_behavior
            assert s.invariants_tested

    def test_scenarios_are_deterministic(self):
        s1 = generate_osint_manipulation(42)
        s2 = generate_osint_manipulation(42)
        assert s1.scenario_id == s2.scenario_id
        assert s1.steps == s2.steps

    def test_different_seeds_produce_different_scenarios(self):
        s1 = generate_osint_manipulation(42)
        s2 = generate_osint_manipulation(99)
        assert s1.scenario_id != s2.scenario_id


class TestAdversarialSimulator:
    """Test the adversarial simulator engine."""

    def test_run_single_scenario(self):
        sim = AdversarialSimulator()
        scenario = generate_osint_manipulation(42)
        result = sim.run_scenario(scenario)
        assert result.scenario_id == scenario.scenario_id
        assert result.steps_executed > 0

    def test_run_all_scenarios_no_invariant_violations(self):
        sim = AdversarialSimulator()
        results = sim.run_all_scenarios(base_seed=42)
        assert len(results) == 8

        for result in results:
            assert result.passed, (
                f"Scenario {result.scenario_id} failed: "
                f"{result.invariant_violations}"
            )

    def test_osint_alone_stays_calm(self):
        sim = AdversarialSimulator()
        scenario = generate_osint_manipulation(42)
        result = sim.run_scenario(scenario)
        assert result.passed
        # OSINT alone should not reach CONFIRMED
        assert result.final_alert_level != "CONFIRMED"

    def test_conflicting_signals_stay_calm(self):
        sim = AdversarialSimulator()
        scenario = generate_conflicting_signals(42)
        result = sim.run_scenario(scenario)
        assert result.passed
        # Conflicting signals should not escalate far
        assert result.final_alert_level in ("NORMAL", "ELEVATED")

    def test_sensor_drift_tracked(self):
        sim = AdversarialSimulator()
        scenario = generate_sensor_drift(42)
        result = sim.run_scenario(scenario)
        assert result.passed

    def test_total_data_loss_handled(self):
        sim = AdversarialSimulator()
        scenario = generate_total_data_loss(42)
        result = sim.run_scenario(scenario)
        assert result.passed

    def test_multi_seed_run(self):
        """Run 10 iterations with different seeds — no violations."""
        sim = AdversarialSimulator()
        results = sim.run_continuous(base_seed=100, iterations=10)
        failures = [r for r in results if not r.passed]
        assert len(failures) == 0, (
            f"{len(failures)} failures out of {len(results)}: "
            f"{[f.scenario_id for f in failures]}"
        )
