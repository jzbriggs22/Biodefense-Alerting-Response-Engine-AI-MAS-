"""
Adversarial scenario generators for the Biodefense Alerting & Response Engine.

Each scenario represents a way the environment can be hostile, ambiguous,
or misleading. Scenarios are designed to break the system — if they don't,
that's evidence of robustness.

Every scenario is:
  - Tagged with a unique identifier
  - Replayable (deterministic given the same seed)
  - Persisted as a regression case

The simulator assumes the universe is adversarial and uncooperative.

TRACEABILITY: spec/biodefense.tla :: AdversarialModel
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.types import BoundedSignal


# ---------------------------------------------------------------------------
# Scenario Categories
# ---------------------------------------------------------------------------

class ScenarioCategory(Enum):
    """Categories of adversarial scenarios."""
    OSINT_MANIPULATION = auto()      # Fabricated or distorted OSINT
    SENSOR_DRIFT = auto()            # Gradual sensor miscalibration
    CORRELATED_NOISE = auto()        # Multiple sensors fail together
    TIME_DELAY = auto()              # Data arrives late
    TIME_REORDER = auto()            # Data arrives out of order
    PARTIAL_DATA_LOSS = auto()       # Some data sources go silent
    TOTAL_DATA_LOSS = auto()         # All data sources go silent
    CONFLICTING_SIGNALS = auto()     # Plausible but contradictory data
    HUMAN_DELAY = auto()             # Human-in-the-loop doesn't respond
    HUMAN_ERROR = auto()             # Human provides wrong input
    CONFIDENCE_INFLATION = auto()    # ML model overconfident
    CONFIDENCE_COLLAPSE = auto()     # ML model suddenly uncertain
    REPLAY_ATTACK = auto()           # Old data replayed as new
    GRADUAL_ESCALATION = auto()      # Slow ramp designed to avoid thresholds
    COORDINATED_SPOOFING = auto()    # Multiple sources spoofed simultaneously


# ---------------------------------------------------------------------------
# Scenario Definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AdversarialScenario:
    """
    A single adversarial scenario definition.

    scenario_id: Unique identifier, deterministic
    category: What kind of adversarial behavior
    description: Human-readable description
    seed: Random seed for reproducibility
    steps: Ordered list of adversarial actions to take
    expected_system_behavior: What the system SHOULD do
    invariants_tested: Which invariants this scenario targets
    """
    scenario_id: str
    category: ScenarioCategory
    description: str
    seed: int
    steps: Tuple[Dict[str, Any], ...]
    expected_system_behavior: str
    invariants_tested: Tuple[str, ...]


# ---------------------------------------------------------------------------
# Scenario Generators
# ---------------------------------------------------------------------------

def generate_osint_manipulation(seed: int) -> AdversarialScenario:
    """
    Generate a scenario where OSINT feeds contain fabricated threat data.

    The adversary injects multiple high-severity reports from
    apparently independent sources, all pointing to a non-existent threat.
    """
    rng = random.Random(seed)

    n_fake_reports = rng.randint(3, 10)
    threat_types = ["anthrax", "smallpox", "plague", "botulism", "tularemia"]

    steps = []
    for i in range(n_fake_reports):
        steps.append({
            "action": "inject_osint_report",
            "data": {
                "source": f"fake_source_{rng.randint(1, 5)}",
                "threat_type": rng.choice(threat_types),
                "severity_score": rng.uniform(0.7, 1.0),
                "corroboration_count": rng.randint(0, 3),
                "timestamp": 1000 + i * 10,
                "evidence_id": f"fake_evidence_{seed}_{i}",
            },
        })

    return AdversarialScenario(
        scenario_id=f"OSINT_MANIP_{seed}",
        category=ScenarioCategory.OSINT_MANIPULATION,
        description=(
            f"Inject {n_fake_reports} fabricated OSINT reports with "
            f"high severity to trigger false escalation"
        ),
        seed=seed,
        steps=tuple(steps),
        expected_system_behavior=(
            "System may escalate to ELEVATED based on OSINT signals but "
            "MUST NOT reach CONFIRMED without sensor or epi corroboration. "
            "OSINT agent confidence is capped at 0.6, which is insufficient "
            "alone for SUSPECTED threshold."
        ),
        invariants_tested=(
            "INV-1:NoSingleAgentEscalation",
            "INV-2:SeverityMonotonicWithCertainty",
            "INV-4:UncertaintySurfaced",
        ),
    )


def generate_sensor_drift(seed: int) -> AdversarialScenario:
    """
    Generate a scenario where sensors gradually drift out of calibration.

    Readings slowly increase over time, simulating a calibration fault
    that could be mistaken for a real threat.
    """
    rng = random.Random(seed)

    n_readings = 20
    drift_rate = rng.uniform(0.01, 0.05)  # Per-step drift

    steps = []
    for i in range(n_readings):
        drifted_value = min(1.0, 0.1 + (drift_rate * i) + rng.gauss(0, 0.02))
        steps.append({
            "action": "inject_sensor_reading",
            "data": {
                "sensor_id": "drifting_sensor_001",
                "reading_type": "particulate_bio",
                "normalized_value": max(0.0, min(1.0, drifted_value)),
                "calibration_confidence": max(0.0, 0.9 - (i * 0.02)),
                "timestamp": 1000 + i * 5,
                "evidence_id": f"drift_{seed}_{i}",
            },
        })

    return AdversarialScenario(
        scenario_id=f"SENSOR_DRIFT_{seed}",
        category=ScenarioCategory.SENSOR_DRIFT,
        description=(
            f"Simulate gradual sensor drift at rate {drift_rate:.3f}/step "
            f"over {n_readings} readings"
        ),
        seed=seed,
        steps=tuple(steps),
        expected_system_behavior=(
            "System should track increasing sensor values but the declining "
            "calibration_confidence should cause the signal confidence to "
            "decrease, producing higher uncertainty. The system should NOT "
            "escalate to CONFIRMED based on drifting sensor data alone."
        ),
        invariants_tested=(
            "INV-1:NoSingleAgentEscalation",
            "INV-4:UncertaintySurfaced",
            "INV-7:SignalBounds",
        ),
    )


def generate_correlated_noise(seed: int) -> AdversarialScenario:
    """
    Generate a scenario where multiple sensors produce correlated noise.

    This simulates a common-mode failure (e.g., power supply glitch)
    that affects multiple sensors simultaneously, creating the appearance
    of a real event.
    """
    rng = random.Random(seed)

    n_sensors = rng.randint(3, 6)
    n_timesteps = 10
    noise_base = rng.uniform(0.5, 0.9)

    steps = []
    for t in range(n_timesteps):
        common_noise = rng.gauss(0, 0.1)  # Correlated component
        for s in range(n_sensors):
            value = max(0.0, min(1.0,
                noise_base + common_noise + rng.gauss(0, 0.02)
            ))
            steps.append({
                "action": "inject_sensor_reading",
                "data": {
                    "sensor_id": f"corr_sensor_{s}",
                    "reading_type": "bio_aerosol",
                    "normalized_value": value,
                    "calibration_confidence": 0.8,
                    "timestamp": 1000 + t * 5,
                    "evidence_id": f"corr_{seed}_{t}_{s}",
                },
            })

    return AdversarialScenario(
        scenario_id=f"CORR_NOISE_{seed}",
        category=ScenarioCategory.CORRELATED_NOISE,
        description=(
            f"Simulate correlated noise across {n_sensors} sensors "
            f"with base level {noise_base:.2f}"
        ),
        seed=seed,
        steps=tuple(steps),
        expected_system_behavior=(
            "The system sees multiple sensors reporting similar values, "
            "which looks like corroboration. However, all signals come from "
            "the same agent (sensor_monitor), so INV-1 prevents single-agent "
            "escalation above ELEVATED without other agent types concurring."
        ),
        invariants_tested=(
            "INV-1:NoSingleAgentEscalation",
            "INV-2:SeverityMonotonicWithCertainty",
            "INV-8:NoLevelSkipping",
        ),
    )


def generate_total_data_loss(seed: int) -> AdversarialScenario:
    """
    Generate a scenario where all data sources go silent.

    The system must handle the absence of data gracefully — no data
    is not the same as good data.
    """
    steps = [
        {"action": "stop_all_feeds", "data": {"timestamp": 1000}},
        {"action": "tick", "data": {"count": 20}},
    ]

    return AdversarialScenario(
        scenario_id=f"TOTAL_LOSS_{seed}",
        category=ScenarioCategory.TOTAL_DATA_LOSS,
        description="All data feeds stop simultaneously",
        seed=seed,
        steps=tuple(steps),
        expected_system_behavior=(
            "System should maintain current alert level with increasing "
            "uncertainty. No escalation — absence of data is not evidence "
            "of threat. No de-escalation — absence of data is not evidence "
            "of safety. Uncertainty should approach 1.0."
        ),
        invariants_tested=(
            "INV-4:UncertaintySurfaced",
            "INV-2:SeverityMonotonicWithCertainty",
        ),
    )


def generate_conflicting_signals(seed: int) -> AdversarialScenario:
    """
    Generate a scenario with plausible but contradictory signals.

    OSINT says outbreak, sensors say normal, epi says unknown.
    The system must not oscillate and must surface the conflict.
    """
    rng = random.Random(seed)

    steps = [
        # OSINT: high threat
        {
            "action": "inject_osint_report",
            "data": {
                "source": "who_feed",
                "threat_type": "novel_respiratory",
                "severity_score": 0.85,
                "corroboration_count": 2,
                "timestamp": 1000,
                "evidence_id": f"conflict_osint_{seed}",
            },
        },
        # Sensor: normal
        {
            "action": "inject_sensor_reading",
            "data": {
                "sensor_id": "primary_bio",
                "reading_type": "aerosol_bio",
                "normalized_value": 0.1,
                "calibration_confidence": 0.9,
                "timestamp": 1001,
                "evidence_id": f"conflict_sensor_{seed}",
            },
        },
        # Epi: no signal
        {
            "action": "inject_epi_indicator",
            "data": {
                "indicator_type": "syndromic_surveillance",
                "normalized_severity": 0.05,
                "lab_confirmed": False,
                "sample_size": 0,
                "timestamp": 1002,
                "evidence_id": f"conflict_epi_{seed}",
            },
        },
        {"action": "evaluate", "data": {}},
    ]

    return AdversarialScenario(
        scenario_id=f"CONFLICT_{seed}",
        category=ScenarioCategory.CONFLICTING_SIGNALS,
        description="OSINT high, sensors normal, epi silent — contradictory signals",
        seed=seed,
        steps=tuple(steps),
        expected_system_behavior=(
            "System should remain at NORMAL or ELEVATED at most. The low "
            "sensor and epi signals should prevent escalation despite alarming "
            "OSINT. Uncertainty should be HIGH because the signals conflict. "
            "The system must not oscillate between levels."
        ),
        invariants_tested=(
            "INV-1:NoSingleAgentEscalation",
            "INV-2:SeverityMonotonicWithCertainty",
            "INV-4:UncertaintySurfaced",
            "INV-6:CausalExplanationRequired",
        ),
    )


def generate_time_reorder(seed: int) -> AdversarialScenario:
    """
    Generate a scenario where signals arrive out of temporal order.

    Older signals arrive after newer ones. The system must use
    monotonic timestamps, not wall clock, so this should be handled.
    """
    rng = random.Random(seed)

    # Generate signals with scrambled timestamps
    signals_data = []
    for i in range(8):
        signals_data.append({
            "action": "inject_sensor_reading",
            "data": {
                "sensor_id": "reorder_sensor",
                "reading_type": "bio_detect",
                "normalized_value": rng.uniform(0.2, 0.6),
                "calibration_confidence": 0.7,
                "timestamp": 1000 + rng.randint(0, 100),  # Out of order
                "evidence_id": f"reorder_{seed}_{i}",
            },
        })

    # Scramble delivery order
    rng.shuffle(signals_data)

    return AdversarialScenario(
        scenario_id=f"TIME_REORDER_{seed}",
        category=ScenarioCategory.TIME_REORDER,
        description="Signals arrive with out-of-order timestamps",
        seed=seed,
        steps=tuple(signals_data),
        expected_system_behavior=(
            "System should process signals by arrival order using monotonic "
            "clock, not by embedded timestamps. Certainty calculations should "
            "be stable regardless of timestamp ordering."
        ),
        invariants_tested=(
            "INV-5:DeterministicReplay",
            "INV-7:SignalBounds",
        ),
    )


def generate_human_delay(seed: int) -> AdversarialScenario:
    """
    Generate a scenario where a human-in-the-loop fails to respond.

    The system has escalated to SUSPECTED and needs human confirmation
    to reach CONFIRMED, but the human doesn't respond.
    """
    steps = [
        # Build up to SUSPECTED with legitimate multi-agent signals
        {
            "action": "inject_sensor_reading",
            "data": {
                "sensor_id": "primary_bio",
                "reading_type": "aerosol_detect",
                "normalized_value": 0.75,
                "calibration_confidence": 0.85,
                "timestamp": 1000,
                "evidence_id": f"hdelay_sensor_{seed}",
            },
        },
        {
            "action": "inject_epi_indicator",
            "data": {
                "indicator_type": "case_cluster",
                "normalized_severity": 0.7,
                "lab_confirmed": True,
                "sample_size": 10,
                "timestamp": 1001,
                "evidence_id": f"hdelay_epi_{seed}",
            },
        },
        {"action": "evaluate", "data": {}},
        # Now wait — human doesn't respond for many ticks
        {"action": "tick", "data": {"count": 50}},
        {"action": "evaluate", "data": {}},
    ]

    return AdversarialScenario(
        scenario_id=f"HUMAN_DELAY_{seed}",
        category=ScenarioCategory.HUMAN_DELAY,
        description="Human fails to respond after escalation to SUSPECTED",
        seed=seed,
        steps=tuple(steps),
        expected_system_behavior=(
            "System should hold at SUSPECTED or de-escalate if signals decay. "
            "It MUST NOT auto-escalate to CONFIRMED without additional evidence. "
            "The human delay is surfaced as increased uncertainty."
        ),
        invariants_tested=(
            "INV-3:SafeModeBlocksEscalation",
            "INV-4:UncertaintySurfaced",
            "INV-2:SeverityMonotonicWithCertainty",
        ),
    )


def generate_gradual_escalation_attack(seed: int) -> AdversarialScenario:
    """
    Generate a scenario where an adversary slowly ramps signal values
    to avoid threshold detection — a "boiling frog" attack.
    """
    rng = random.Random(seed)

    n_steps = 40
    steps = []
    for i in range(n_steps):
        # Very slow ramp — each step barely above noise
        value = min(1.0, 0.05 + (i * 0.02) + rng.gauss(0, 0.01))
        steps.append({
            "action": "inject_sensor_reading",
            "data": {
                "sensor_id": "gradual_sensor",
                "reading_type": "bio_particulate",
                "normalized_value": max(0.0, value),
                "calibration_confidence": 0.8,
                "timestamp": 1000 + i * 5,
                "evidence_id": f"gradual_{seed}_{i}",
            },
        })
        if i % 5 == 4:
            steps.append({"action": "evaluate", "data": {}})

    return AdversarialScenario(
        scenario_id=f"GRADUAL_ESC_{seed}",
        category=ScenarioCategory.GRADUAL_ESCALATION,
        description=f"Slow ramp over {n_steps} steps to avoid thresholds",
        seed=seed,
        steps=tuple(steps),
        expected_system_behavior=(
            "System should escalate normally as certainty crosses thresholds. "
            "The hysteresis gaps prevent oscillation during the ramp. "
            "Escalation must still require multi-agent quorum."
        ),
        invariants_tested=(
            "INV-1:NoSingleAgentEscalation",
            "INV-2:SeverityMonotonicWithCertainty",
            "INV-8:NoLevelSkipping",
        ),
    )


# ---------------------------------------------------------------------------
# Scenario Registry
# ---------------------------------------------------------------------------

ALL_SCENARIO_GENERATORS = [
    generate_osint_manipulation,
    generate_sensor_drift,
    generate_correlated_noise,
    generate_total_data_loss,
    generate_conflicting_signals,
    generate_time_reorder,
    generate_human_delay,
    generate_gradual_escalation_attack,
]


def generate_all_scenarios(base_seed: int = 42) -> List[AdversarialScenario]:
    """Generate one instance of each scenario type."""
    return [gen(base_seed) for gen in ALL_SCENARIO_GENERATORS]
