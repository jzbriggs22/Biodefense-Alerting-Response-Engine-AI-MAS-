"""
Continuous Adversarial Simulator for the Biodefense Alerting & Response Engine.

This simulator runs ALONGSIDE the system, continuously generating
adversarial scenarios and verifying that invariants hold.

Design principle: The simulator assumes the universe is adversarial
and uncooperative. It generates inputs that a competent adversary
would use to cause false alerts or suppress real ones.

Every adversarial run is:
  - Tagged with a unique run ID
  - Replayable (given the same scenario and seed)
  - Persisted as a regression case with full results

TRACEABILITY: spec/biodefense.tla :: AdversarialSimulator
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.engine import BiodefenseEngine, EngineConfig
from src.agents.osint_agent import OSINTAgent
from src.agents.sensor_agent import SensorAgent
from src.agents.epi_agent import EpidemiologicalAgent
from src.invariants import InvariantResult
from src.types import AlertLevel, SystemSnapshot

from .scenarios import (
    AdversarialScenario,
    ALL_SCENARIO_GENERATORS,
    ScenarioCategory,
)


# ---------------------------------------------------------------------------
# Simulation Result
# ---------------------------------------------------------------------------

@dataclass
class SimulationResult:
    """Result of running one adversarial scenario against the engine."""
    scenario_id: str
    category: str
    seed: int
    passed: bool
    invariant_violations: List[Dict[str, Any]]
    state_trace: List[Dict[str, Any]]
    final_alert_level: str
    final_uncertainty: float
    expected_behavior: str
    actual_behavior: str
    steps_executed: int
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "category": self.category,
            "seed": self.seed,
            "passed": self.passed,
            "invariant_violations": self.invariant_violations,
            "state_trace": self.state_trace,
            "final_alert_level": self.final_alert_level,
            "final_uncertainty": self.final_uncertainty,
            "expected_behavior": self.expected_behavior,
            "actual_behavior": self.actual_behavior,
            "steps_executed": self.steps_executed,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Adversarial Simulator
# ---------------------------------------------------------------------------

class AdversarialSimulator:
    """
    Continuous adversarial simulator.

    Usage:
        sim = AdversarialSimulator()
        results = sim.run_all_scenarios(seed=42)
        sim.persist_results(results, "regression/run_001.json")

    For continuous operation:
        sim.run_continuous(base_seed=42, iterations=1000)
    """

    def __init__(self, regression_dir: str = "regression"):
        self._regression_dir = regression_dir

    def run_scenario(self, scenario: AdversarialScenario) -> SimulationResult:
        """
        Run a single adversarial scenario against a fresh engine instance.

        Returns a SimulationResult with full trace and invariant check results.
        """
        # Fresh engine for each scenario — no state leakage
        engine = BiodefenseEngine(EngineConfig(enable_runtime_invariant_checks=True))
        engine.register_agent(OSINTAgent())
        engine.register_agent(SensorAgent())
        engine.register_agent(EpidemiologicalAgent())

        state_trace: List[Dict[str, Any]] = []
        steps_executed = 0

        try:
            for step in scenario.steps:
                action = step["action"]
                data = step.get("data", {})

                if action == "inject_osint_report":
                    engine.ingest("osint_monitor", {"reports": [data]})

                elif action == "inject_sensor_reading":
                    engine.ingest("sensor_monitor", {"readings": [data]})

                elif action == "inject_epi_indicator":
                    engine.ingest("epi_analyst", {"indicators": [data]})

                elif action == "evaluate":
                    engine.evaluate()

                elif action == "tick":
                    count = data.get("count", 1)
                    for _ in range(count):
                        engine.tick()

                elif action == "stop_all_feeds":
                    # Simulate data loss by just ticking without new data
                    pass

                else:
                    pass  # Unknown actions are no-ops

                # Record state after each step
                snap = engine.snapshot
                state_trace.append({
                    "step": steps_executed,
                    "action": action,
                    "alert_level": snap.alert_level.name,
                    "net_certainty": snap.net_certainty,
                    "uncertainty": snap.uncertainty,
                    "safe_mode": snap.safe_mode,
                    "n_signals": len(snap.pending_signals),
                })
                steps_executed += 1

        except Exception as e:
            return SimulationResult(
                scenario_id=scenario.scenario_id,
                category=scenario.category.name,
                seed=scenario.seed,
                passed=False,
                invariant_violations=[],
                state_trace=state_trace,
                final_alert_level="ERROR",
                final_uncertainty=1.0,
                expected_behavior=scenario.expected_system_behavior,
                actual_behavior=f"Exception: {e}",
                steps_executed=steps_executed,
                error=str(e),
            )

        # Check results
        violations = engine.invariant_violations
        violation_dicts = [
            {"name": v.name, "description": v.description,
             "detail": v.violation_detail}
            for v in violations
        ]

        final_snap = engine.snapshot
        passed = len(violations) == 0

        return SimulationResult(
            scenario_id=scenario.scenario_id,
            category=scenario.category.name,
            seed=scenario.seed,
            passed=passed,
            invariant_violations=violation_dicts,
            state_trace=state_trace,
            final_alert_level=final_snap.alert_level.name,
            final_uncertainty=final_snap.uncertainty,
            expected_behavior=scenario.expected_system_behavior,
            actual_behavior=self._describe_actual(state_trace, final_snap),
            steps_executed=steps_executed,
        )

    def run_all_scenarios(self, base_seed: int = 42) -> List[SimulationResult]:
        """Run all scenario generators with a given seed."""
        results = []
        for generator in ALL_SCENARIO_GENERATORS:
            scenario = generator(base_seed)
            result = self.run_scenario(scenario)
            results.append(result)
        return results

    def run_continuous(
        self,
        base_seed: int = 42,
        iterations: int = 100,
    ) -> List[SimulationResult]:
        """
        Run scenarios continuously with varying seeds.

        Each iteration uses a different seed derived from the base seed,
        generating different instances of each scenario type.
        """
        all_results = []
        for i in range(iterations):
            seed = base_seed + i
            for generator in ALL_SCENARIO_GENERATORS:
                scenario = generator(seed)
                result = self.run_scenario(scenario)
                all_results.append(result)

                # Persist failures immediately as regression cases
                if not result.passed:
                    self._persist_single(result)

        return all_results

    def persist_results(
        self,
        results: List[SimulationResult],
        filepath: str,
    ) -> None:
        """Persist simulation results to a JSON file."""
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(
                {
                    "timestamp": time.time(),
                    "total_scenarios": len(results),
                    "passed": sum(1 for r in results if r.passed),
                    "failed": sum(1 for r in results if not r.passed),
                    "results": [r.to_dict() for r in results],
                },
                f,
                indent=2,
            )

    def _persist_single(self, result: SimulationResult) -> None:
        """Persist a single failure as a regression case."""
        os.makedirs(self._regression_dir, exist_ok=True)
        filepath = os.path.join(
            self._regression_dir,
            f"{result.scenario_id}.json",
        )
        with open(filepath, "w") as f:
            json.dump(result.to_dict(), f, indent=2)

    def _describe_actual(
        self,
        trace: List[Dict[str, Any]],
        final: SystemSnapshot,
    ) -> str:
        """Generate a human-readable description of actual behavior."""
        levels_seen = set()
        for entry in trace:
            levels_seen.add(entry["alert_level"])

        transitions = []
        for i in range(1, len(trace)):
            if trace[i]["alert_level"] != trace[i-1]["alert_level"]:
                transitions.append(
                    f"{trace[i-1]['alert_level']} -> {trace[i]['alert_level']} "
                    f"at step {i}"
                )

        return (
            f"Final level: {final.alert_level.name}, "
            f"uncertainty: {final.uncertainty:.3f}. "
            f"Levels visited: {sorted(levels_seen)}. "
            f"Transitions: {transitions if transitions else 'none'}"
        )
