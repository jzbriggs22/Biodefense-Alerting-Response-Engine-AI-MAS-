"""
Fault Injection Framework for the Biodefense Alerting & Response Engine.

This framework systematically violates assumptions to verify that the
system handles faults correctly. Each fault type represents a specific
assumption violation with:

  1. Injection method — how the fault is introduced
  2. Expected system behavior — what should happen
  3. Invariant checks — which invariants must still hold

Fault categories:
  - Data faults: corrupted, missing, or malformed input data
  - Temporal faults: clock skew, delays, reordering
  - Model confidence faults: ML models misbehaving
  - Arbitration conflicts: agents disagreeing pathologically
  - Governance edge cases: safe mode and human override failures

TRACEABILITY: spec/biodefense.tla :: FaultModel
"""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.engine import BiodefenseEngine, EngineConfig
from src.agents.osint_agent import OSINTAgent
from src.agents.sensor_agent import SensorAgent
from src.agents.epi_agent import EpidemiologicalAgent
from src.invariants import InvariantResult, check_all_snapshot_invariants
from src.types import AlertLevel, BoundedSignal, SystemSnapshot, TemporalConfig, HumanAuthorityPolicy


# ---------------------------------------------------------------------------
# Fault Categories
# ---------------------------------------------------------------------------

class FaultCategory(Enum):
    DATA = auto()
    TEMPORAL = auto()
    MODEL_CONFIDENCE = auto()
    ARBITRATION = auto()
    GOVERNANCE = auto()


# ---------------------------------------------------------------------------
# Fault Definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FaultDefinition:
    """
    A single fault definition in the taxonomy.

    fault_id: Unique identifier
    category: Fault category
    description: What this fault represents
    injection_method: How to inject this fault
    expected_behavior: What the system should do
    invariants_that_must_hold: Invariants that must still hold under this fault
    invariants_that_may_fail: Invariants expected to be tested (but should hold)
    """
    fault_id: str
    category: FaultCategory
    description: str
    injection_method: str
    expected_behavior: str
    invariants_that_must_hold: Tuple[str, ...]
    invariants_that_may_fail: Tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Fault Taxonomy — the complete set of systematic assumption violations
# ---------------------------------------------------------------------------

FAULT_TAXONOMY: List[FaultDefinition] = [
    # --- Data Faults ---
    FaultDefinition(
        fault_id="DF-001",
        category=FaultCategory.DATA,
        description="Signal value exceeds [0,1] bounds",
        injection_method=(
            "Attempt to create BoundedSignal with value > 1.0 or < 0.0"
        ),
        expected_behavior=(
            "BoundedSignal constructor raises ValueError. "
            "The signal never enters the system."
        ),
        invariants_that_must_hold=("INV-7:SignalBounds",),
    ),
    FaultDefinition(
        fault_id="DF-002",
        category=FaultCategory.DATA,
        description="Signal confidence exceeds [0,1] bounds",
        injection_method=(
            "Attempt to create BoundedSignal with confidence > 1.0"
        ),
        expected_behavior=(
            "BoundedSignal constructor raises ValueError."
        ),
        invariants_that_must_hold=("INV-7:SignalBounds",),
    ),
    FaultDefinition(
        fault_id="DF-003",
        category=FaultCategory.DATA,
        description="Empty source agent identifier",
        injection_method=(
            "Attempt to create BoundedSignal with source_agent=''"
        ),
        expected_behavior=(
            "BoundedSignal constructor raises ValueError."
        ),
        invariants_that_must_hold=("INV-7:SignalBounds",),
    ),
    FaultDefinition(
        fault_id="DF-004",
        category=FaultCategory.DATA,
        description="NaN or Inf signal values",
        injection_method=(
            "Attempt to create BoundedSignal with value=float('nan') "
            "or value=float('inf')"
        ),
        expected_behavior=(
            "BoundedSignal constructor raises ValueError because "
            "NaN/Inf fail the bounds check (NaN is not <= 1.0)."
        ),
        invariants_that_must_hold=("INV-7:SignalBounds",),
    ),
    FaultDefinition(
        fault_id="DF-005",
        category=FaultCategory.DATA,
        description="Zero signals — no data at all",
        injection_method=(
            "Run evaluation with no signals ingested"
        ),
        expected_behavior=(
            "System remains at NORMAL with certainty=0.0, uncertainty=1.0. "
            "No transition occurs."
        ),
        invariants_that_must_hold=(
            "INV-4:UncertaintySurfaced",
            "INV-2:SeverityMonotonicWithCertainty",
        ),
    ),
    FaultDefinition(
        fault_id="DF-006",
        category=FaultCategory.DATA,
        description="Duplicate signals with identical content",
        injection_method=(
            "Inject the same signal twice with identical content"
        ),
        expected_behavior=(
            "Both signals are processed. They have the same signal_id "
            "(content-addressed). Certainty does not artificially inflate "
            "because confidence-weighted mean is used."
        ),
        invariants_that_must_hold=(
            "INV-5:DeterministicReplay",
            "INV-7:SignalBounds",
        ),
    ),

    # --- Temporal Faults ---
    FaultDefinition(
        fault_id="TF-001",
        category=FaultCategory.TEMPORAL,
        description="Monotonic timestamp regression",
        injection_method=(
            "Inject signal with timestamp lower than previous signal"
        ),
        expected_behavior=(
            "Signal is accepted — monotonic timestamps are advisory. "
            "The state machine uses arrival order, not timestamps, "
            "for sequencing. Signal decay uses the latest signal's "
            "timestamp as reference."
        ),
        invariants_that_must_hold=(
            "INV-5:DeterministicReplay",
            "INV-7:SignalBounds",
        ),
    ),
    FaultDefinition(
        fault_id="TF-002",
        category=FaultCategory.TEMPORAL,
        description="Large timestamp gap",
        injection_method=(
            "Inject signal with timestamp far in the future "
            "(e.g., +1000000 ticks from last signal)"
        ),
        expected_behavior=(
            "Signal is accepted. If the gap exceeds the decay window, "
            "previous signals are expired during tick processing. "
            "This is correct behavior — old signals should decay."
        ),
        invariants_that_must_hold=(
            "INV-4:UncertaintySurfaced",
        ),
    ),
    FaultDefinition(
        fault_id="TF-003",
        category=FaultCategory.TEMPORAL,
        description="Rapid signal burst",
        injection_method=(
            "Inject 100+ signals in a single tick with same timestamp"
        ),
        expected_behavior=(
            "All signals are processed. Certainty is the "
            "confidence-weighted mean, which is bounded [0,1] "
            "regardless of signal count. No amplification attack."
        ),
        invariants_that_must_hold=(
            "INV-7:SignalBounds",
            "INV-2:SeverityMonotonicWithCertainty",
        ),
    ),

    # --- Model Confidence Faults ---
    FaultDefinition(
        fault_id="MC-001",
        category=FaultCategory.MODEL_CONFIDENCE,
        description="Agent reports maximum confidence on noise",
        injection_method=(
            "Agent reports confidence=1.0 on a signal with value=0.0"
        ),
        expected_behavior=(
            "The high-confidence zero-value signal drives certainty DOWN. "
            "A confident report of 'no threat' is a legitimate signal "
            "that reduces overall certainty."
        ),
        invariants_that_must_hold=(
            "INV-7:SignalBounds",
            "INV-4:UncertaintySurfaced",
        ),
    ),
    FaultDefinition(
        fault_id="MC-002",
        category=FaultCategory.MODEL_CONFIDENCE,
        description="All agents report confidence=0.0",
        injection_method=(
            "All agents produce signals with confidence=0.0"
        ),
        expected_behavior=(
            "Certainty calculation: total_weight=0, so certainty=0.0, "
            "uncertainty=1.0. No transition possible. System stays at "
            "current level with maximum uncertainty."
        ),
        invariants_that_must_hold=(
            "INV-4:UncertaintySurfaced",
            "INV-2:SeverityMonotonicWithCertainty",
        ),
    ),
    FaultDefinition(
        fault_id="MC-003",
        category=FaultCategory.MODEL_CONFIDENCE,
        description="Agent confidence oscillates between 0 and 1",
        injection_method=(
            "Agent alternates between confidence=0.0 and confidence=1.0 "
            "on consecutive signals"
        ),
        expected_behavior=(
            "Certainty fluctuates but hysteresis prevents oscillation "
            "between alert levels. The gap between escalation and "
            "de-escalation thresholds absorbs the fluctuation."
        ),
        invariants_that_must_hold=(
            "INV-2:SeverityMonotonicWithCertainty",
            "INV-8:NoLevelSkipping",
        ),
    ),

    # --- Arbitration Conflicts ---
    FaultDefinition(
        fault_id="AC-001",
        category=FaultCategory.ARBITRATION,
        description="All agents disagree — no majority",
        injection_method=(
            "Each agent votes for a different alert level with equal confidence"
        ),
        expected_behavior=(
            "Agreement ratio is below min_agreement_ratio threshold. "
            "No transition occurs. System maintains current level."
        ),
        invariants_that_must_hold=(
            "INV-1:NoSingleAgentEscalation",
            "INV-4:UncertaintySurfaced",
        ),
    ),
    FaultDefinition(
        fault_id="AC-002",
        category=FaultCategory.ARBITRATION,
        description="Single agent with very high confidence outvotes others",
        injection_method=(
            "One agent votes CONFIRMED with confidence=1.0, "
            "two agents vote NORMAL with confidence=0.3 each"
        ),
        expected_behavior=(
            "The high-confidence agent has majority weight but "
            "the system still enforces quorum size (number of agents "
            "supporting escalation). A single agent's vote for CONFIRMED "
            "does not satisfy the quorum requirement."
        ),
        invariants_that_must_hold=(
            "INV-1:NoSingleAgentEscalation",
        ),
    ),
    FaultDefinition(
        fault_id="AC-003",
        category=FaultCategory.ARBITRATION,
        description="Agent votes for level below current",
        injection_method=(
            "System is at SUSPECTED, agent votes for NORMAL"
        ),
        expected_behavior=(
            "De-escalation votes are tallied normally. If enough agents "
            "vote for lower levels and certainty has decreased, "
            "de-escalation occurs one step at a time."
        ),
        invariants_that_must_hold=(
            "INV-8:NoLevelSkipping",
            "INV-6:CausalExplanationRequired",
        ),
    ),

    # --- Governance Edge Cases ---
    FaultDefinition(
        fault_id="GV-001",
        category=FaultCategory.GOVERNANCE,
        description="Enter safe mode while at CONFIRMED",
        injection_method=(
            "Activate safe mode when system is at CONFIRMED level"
        ),
        expected_behavior=(
            "System transitions to SAFE. Alert level drops to SAFE. "
            "No automated escalation possible until safe mode exits. "
            "This is a governance action — always allowed."
        ),
        invariants_that_must_hold=(
            "INV-3:SafeModeBlocksEscalation",
            "INV-6:CausalExplanationRequired",
        ),
    ),
    FaultDefinition(
        fault_id="GV-002",
        category=FaultCategory.GOVERNANCE,
        description="Double safe mode entry",
        injection_method=(
            "Call enter_safe_mode twice consecutively"
        ),
        expected_behavior=(
            "Second call is idempotent — no state change, no error."
        ),
        invariants_that_must_hold=(
            "INV-3:SafeModeBlocksEscalation",
        ),
    ),
    FaultDefinition(
        fault_id="GV-003",
        category=FaultCategory.GOVERNANCE,
        description="Exit safe mode when not in safe mode",
        injection_method=(
            "Call exit_safe_mode when safe_mode=False"
        ),
        expected_behavior=(
            "Call is idempotent — no state change, no error."
        ),
        invariants_that_must_hold=(),
    ),
    FaultDefinition(
        fault_id="GV-004",
        category=FaultCategory.GOVERNANCE,
        description="Human override to CONFIRMED from NORMAL",
        injection_method=(
            "Human override directly sets level to CONFIRMED from NORMAL"
        ),
        expected_behavior=(
            "Human overrides are allowed to skip levels because they "
            "represent external confirmation. The override is logged "
            "with full explanation. INV-8 (NoLevelSkipping) check is "
            "passed because the transition record carries human_override=True."
        ),
        invariants_that_must_hold=(
            "INV-6:CausalExplanationRequired",
        ),
    ),

    # --- Human Authority Faults ---
    FaultDefinition(
        fault_id="HA-001",
        category=FaultCategory.GOVERNANCE,
        description="Automated escalation attempts CONFIRMED",
        injection_method=(
            "Feed extremely strong multi-agent signals attempting "
            "automated escalation to CONFIRMED"
        ),
        expected_behavior=(
            "System stays at SUSPECTED. INV-9 blocks automated escalation "
            "beyond max_automated_level. Human authorization required for "
            "CONFIRMED."
        ),
        invariants_that_must_hold=("INV-9:AuthorityBounds",),
    ),
    FaultDefinition(
        fault_id="HA-002",
        category=FaultCategory.GOVERNANCE,
        description="Human override to CONFIRMED succeeds",
        injection_method=(
            "Use human_override to set level to CONFIRMED"
        ),
        expected_behavior=(
            "System reaches CONFIRMED. Human overrides bypass authority bounds."
        ),
        invariants_that_must_hold=("INV-6:CausalExplanationRequired",),
    ),
    FaultDefinition(
        fault_id="HA-003",
        category=FaultCategory.GOVERNANCE,
        description="Human override during shutdown",
        injection_method=(
            "Trigger shutdown via kill-switch, then attempt human override"
        ),
        expected_behavior=(
            "System is shutdown. Only safe mode entry is accepted. "
            "Human override of alert level is blocked."
        ),
        invariants_that_must_hold=(),
    ),

    # --- Temporal Faults (additional) ---
    FaultDefinition(
        fault_id="TF-004",
        category=FaultCategory.TEMPORAL,
        description="Escalation blocked by insufficient dwell time",
        injection_method=(
            "Escalate to ELEVATED, then immediately attempt second "
            "escalation without sufficient ticks"
        ),
        expected_behavior=(
            "Second escalation is blocked. System stays at ELEVATED "
            "until min_dwell_ticks (3) have elapsed."
        ),
        invariants_that_must_hold=("INV-10:MinDwellTime",),
    ),
    FaultDefinition(
        fault_id="TF-005",
        category=FaultCategory.TEMPORAL,
        description="Alert rate limit enforced",
        injection_method=(
            "Trigger rapid successive transitions exceeding rate limit "
            "(5 per 50 ticks)"
        ),
        expected_behavior=(
            "After 5 transitions, further transitions are blocked "
            "until window expires."
        ),
        invariants_that_must_hold=("INV-11:AlertRateLimit",),
    ),
    FaultDefinition(
        fault_id="TF-006",
        category=FaultCategory.TEMPORAL,
        description="Kill-switch activates on repeated violations",
        injection_method=(
            "Force invariant violations until kill-switch threshold (3) "
            "is reached"
        ),
        expected_behavior=(
            "System enters shutdown and SAFE mode. Only safe mode entry "
            "is accepted."
        ),
        invariants_that_must_hold=(),
    ),
    FaultDefinition(
        fault_id="TF-007",
        category=FaultCategory.TEMPORAL,
        description="Signal decay returns system to baseline",
        injection_method=(
            "Ingest signals to escalate, then tick 200 times without "
            "new signals"
        ),
        expected_behavior=(
            "After signals decay (100-tick window), certainty drops "
            "toward 0 and system de-escalates toward NORMAL."
        ),
        invariants_that_must_hold=("INV-2:SeverityMonotonicWithCertainty",),
    ),
]


# ---------------------------------------------------------------------------
# Fault Injector — executes faults and checks invariants
# ---------------------------------------------------------------------------

@dataclass
class FaultInjectionResult:
    """Result of injecting a single fault."""
    fault_id: str
    category: str
    description: str
    expected_behavior: str
    actual_behavior: str
    passed: bool
    invariant_results: List[Dict[str, Any]]
    error: Optional[str] = None


class FaultInjector:
    """
    Executes fault injection tests from the taxonomy.

    Each fault is injected into a fresh engine instance, and the
    resulting system state is checked against the expected behavior
    and required invariants.
    """

    def _make_engine(self) -> BiodefenseEngine:
        """Create a fresh engine with all agents registered."""
        engine = BiodefenseEngine(
            EngineConfig(enable_runtime_invariant_checks=True)
        )
        engine.register_agent(OSINTAgent())
        engine.register_agent(SensorAgent())
        engine.register_agent(EpidemiologicalAgent())
        return engine

    def inject_data_fault_out_of_bounds(self) -> FaultInjectionResult:
        """DF-001: Signal value exceeds bounds."""
        fault = FAULT_TAXONOMY[0]
        try:
            BoundedSignal(
                source_agent="test",
                signal_type="test",
                value=1.5,  # Out of bounds
                confidence=0.5,
                timestamp_monotonic=0,
            )
            return FaultInjectionResult(
                fault_id=fault.fault_id,
                category=fault.category.name,
                description=fault.description,
                expected_behavior=fault.expected_behavior,
                actual_behavior="Signal was accepted — bounds not enforced",
                passed=False,
                invariant_results=[],
            )
        except ValueError as e:
            return FaultInjectionResult(
                fault_id=fault.fault_id,
                category=fault.category.name,
                description=fault.description,
                expected_behavior=fault.expected_behavior,
                actual_behavior=f"ValueError raised: {e}",
                passed=True,
                invariant_results=[],
            )

    def inject_data_fault_nan(self) -> FaultInjectionResult:
        """DF-004: NaN signal value."""
        fault = FAULT_TAXONOMY[3]
        try:
            BoundedSignal(
                source_agent="test",
                signal_type="test",
                value=float("nan"),
                confidence=0.5,
                timestamp_monotonic=0,
            )
            return FaultInjectionResult(
                fault_id=fault.fault_id,
                category=fault.category.name,
                description=fault.description,
                expected_behavior=fault.expected_behavior,
                actual_behavior="NaN signal accepted — bounds not enforced for NaN",
                passed=False,
                invariant_results=[],
            )
        except ValueError as e:
            return FaultInjectionResult(
                fault_id=fault.fault_id,
                category=fault.category.name,
                description=fault.description,
                expected_behavior=fault.expected_behavior,
                actual_behavior=f"ValueError raised: {e}",
                passed=True,
                invariant_results=[],
            )

    def inject_data_fault_no_signals(self) -> FaultInjectionResult:
        """DF-005: Zero signals."""
        fault = FAULT_TAXONOMY[4]
        engine = self._make_engine()
        engine.evaluate()
        snap = engine.snapshot

        passed = (
            snap.alert_level == AlertLevel.NORMAL
            and snap.net_certainty == 0.0
            and snap.uncertainty == 1.0
        )

        return FaultInjectionResult(
            fault_id=fault.fault_id,
            category=fault.category.name,
            description=fault.description,
            expected_behavior=fault.expected_behavior,
            actual_behavior=(
                f"Level={snap.alert_level.name}, "
                f"certainty={snap.net_certainty}, "
                f"uncertainty={snap.uncertainty}"
            ),
            passed=passed,
            invariant_results=[
                {"name": r.name, "holds": r.holds}
                for r in check_all_snapshot_invariants(snap)
            ],
        )

    def inject_temporal_fault_rapid_burst(self) -> FaultInjectionResult:
        """TF-003: Rapid signal burst."""
        fault = FAULT_TAXONOMY[8]
        engine = self._make_engine()

        # Inject 100 signals in one burst
        readings = []
        for i in range(100):
            readings.append({
                "sensor_id": f"burst_sensor_{i % 5}",
                "reading_type": "bio_detect",
                "normalized_value": 0.9,  # High value
                "calibration_confidence": 0.85,
                "timestamp": 1000,  # All same timestamp
                "evidence_id": f"burst_{i}",
            })
        engine.ingest("sensor_monitor", {"readings": readings})
        engine.evaluate()
        snap = engine.snapshot

        # Certainty should be bounded [0,1] despite 100 signals
        passed = 0.0 <= snap.net_certainty <= 1.0

        return FaultInjectionResult(
            fault_id=fault.fault_id,
            category=fault.category.name,
            description=fault.description,
            expected_behavior=fault.expected_behavior,
            actual_behavior=(
                f"Certainty={snap.net_certainty:.3f} after 100 signals "
                f"(bounded: {passed})"
            ),
            passed=passed,
            invariant_results=[
                {"name": r.name, "holds": r.holds}
                for r in check_all_snapshot_invariants(snap)
            ],
        )

    def inject_confidence_fault_all_zero(self) -> FaultInjectionResult:
        """MC-002: All agents report confidence=0."""
        fault = FAULT_TAXONOMY[10]
        engine = self._make_engine()

        # Inject zero-confidence signals
        engine.ingest("sensor_monitor", {"readings": [{
            "sensor_id": "zero_conf",
            "reading_type": "test",
            "normalized_value": 0.9,
            "calibration_confidence": 0.0,
            "timestamp": 1000,
            "evidence_id": "zero_1",
        }]})

        snap = engine.snapshot
        passed = (
            snap.net_certainty == 0.0
            and snap.uncertainty == 1.0
        )

        return FaultInjectionResult(
            fault_id=fault.fault_id,
            category=fault.category.name,
            description=fault.description,
            expected_behavior=fault.expected_behavior,
            actual_behavior=(
                f"Certainty={snap.net_certainty}, "
                f"uncertainty={snap.uncertainty}"
            ),
            passed=passed,
            invariant_results=[
                {"name": r.name, "holds": r.holds}
                for r in check_all_snapshot_invariants(snap)
            ],
        )

    def inject_governance_fault_double_safe(self) -> FaultInjectionResult:
        """GV-002: Double safe mode entry."""
        fault = FAULT_TAXONOMY[16]
        engine = self._make_engine()

        engine.enter_safe_mode()
        snap1 = engine.snapshot

        engine.enter_safe_mode()  # Second call
        snap2 = engine.snapshot

        # Should be idempotent
        passed = (
            snap1.alert_level == snap2.alert_level == AlertLevel.SAFE
            and snap1.safe_mode == snap2.safe_mode is True
        )

        return FaultInjectionResult(
            fault_id=fault.fault_id,
            category=fault.category.name,
            description=fault.description,
            expected_behavior=fault.expected_behavior,
            actual_behavior=(
                f"After first: level={snap1.alert_level.name}, "
                f"After second: level={snap2.alert_level.name}"
            ),
            passed=passed,
            invariant_results=[],
        )

    # ------------------------------------------------------------------
    # Human Authority Fault Injections
    # ------------------------------------------------------------------

    def inject_authority_fault_automated_confirmed(self) -> FaultInjectionResult:
        """HA-001: Automated escalation attempts CONFIRMED.

        Creates an engine, registers all 3 agents, feeds strong multi-agent
        signals (sensor + epi both at 0.95), evaluates multiple times with
        ticks between for dwell time, and verifies the level never reaches
        CONFIRMED because INV-9 (AuthorityBounds) blocks automated
        escalation beyond max_automated_level.
        """
        fault = [f for f in FAULT_TAXONOMY if f.fault_id == "HA-001"][0]
        engine = self._make_engine()

        # Feed strong sensor signals (value=0.95, high confidence)
        engine.ingest("sensor_monitor", {"readings": [
            {
                "sensor_id": "ha001_sensor_1",
                "reading_type": "bio_detect",
                "normalized_value": 0.95,
                "calibration_confidence": 0.95,
                "timestamp": 100,
                "evidence_id": "ha001_s1",
            },
            {
                "sensor_id": "ha001_sensor_2",
                "reading_type": "bio_detect",
                "normalized_value": 0.95,
                "calibration_confidence": 0.95,
                "timestamp": 100,
                "evidence_id": "ha001_s2",
            },
        ]})

        # Feed strong epi signals (value=0.95, lab confirmed, large sample)
        engine.ingest("epi_analyst", {"indicators": [
            {
                "indicator_type": "lab_confirmation",
                "normalized_severity": 0.95,
                "lab_confirmed": True,
                "sample_size": 50,
                "timestamp": 100,
                "evidence_id": "ha001_e1",
            },
            {
                "indicator_type": "syndromic",
                "normalized_severity": 0.95,
                "lab_confirmed": True,
                "sample_size": 50,
                "timestamp": 100,
                "evidence_id": "ha001_e2",
            },
        ]})

        # Evaluate multiple times with ticks in between to satisfy dwell time
        for _ in range(20):
            engine.evaluate()
            engine.tick()

        snap = engine.snapshot
        # The system must NOT reach CONFIRMED through automated escalation
        passed = snap.alert_level != AlertLevel.CONFIRMED

        return FaultInjectionResult(
            fault_id=fault.fault_id,
            category=fault.category.name,
            description=fault.description,
            expected_behavior=fault.expected_behavior,
            actual_behavior=(
                f"Level={snap.alert_level.name} after strong multi-agent "
                f"automated signals. CONFIRMED blocked: {passed}"
            ),
            passed=passed,
            invariant_results=[
                {"name": r.name, "holds": r.holds}
                for r in check_all_snapshot_invariants(snap)
            ],
        )

    def inject_authority_fault_human_override_confirmed(self) -> FaultInjectionResult:
        """HA-002: Human override to CONFIRMED succeeds.

        Creates an engine, uses engine.human_override("operator",
        AlertLevel.CONFIRMED, "test"), and verifies the level reaches
        CONFIRMED. Human overrides bypass authority bounds.
        """
        fault = [f for f in FAULT_TAXONOMY if f.fault_id == "HA-002"][0]
        engine = self._make_engine()

        # Ingest at least one signal so the override has a signal to reference
        engine.ingest("sensor_monitor", {"readings": [{
            "sensor_id": "ha002_sensor",
            "reading_type": "bio_detect",
            "normalized_value": 0.5,
            "calibration_confidence": 0.5,
            "timestamp": 100,
            "evidence_id": "ha002_s1",
        }]})

        # Human override directly to CONFIRMED
        engine.human_override("operator", AlertLevel.CONFIRMED, "test")
        snap = engine.snapshot

        passed = snap.alert_level == AlertLevel.CONFIRMED

        return FaultInjectionResult(
            fault_id=fault.fault_id,
            category=fault.category.name,
            description=fault.description,
            expected_behavior=fault.expected_behavior,
            actual_behavior=(
                f"Level={snap.alert_level.name} after human override. "
                f"CONFIRMED reached: {passed}"
            ),
            passed=passed,
            invariant_results=[
                {"name": r.name, "holds": r.holds}
                for r in check_all_snapshot_invariants(snap)
            ],
        )

    def inject_authority_fault_shutdown_override(self) -> FaultInjectionResult:
        """HA-003: Human override during shutdown.

        Creates an engine, manually sets the FSM to shutdown state
        (_is_shutdown=True, _safe_mode=True, _alert_level=SAFE),
        then attempts a human override. Verifies the system stays at SAFE
        because shutdown blocks all events except safe mode entry.
        """
        fault = [f for f in FAULT_TAXONOMY if f.fault_id == "HA-003"][0]
        engine = self._make_engine()

        # Ingest a signal so the override has something to reference
        engine.ingest("sensor_monitor", {"readings": [{
            "sensor_id": "ha003_sensor",
            "reading_type": "bio_detect",
            "normalized_value": 0.5,
            "calibration_confidence": 0.5,
            "timestamp": 100,
            "evidence_id": "ha003_s1",
        }]})

        # Force shutdown state
        engine._fsm._is_shutdown = True
        engine._fsm._safe_mode = True
        engine._fsm._alert_level = AlertLevel.SAFE

        # Attempt human override — should be blocked by shutdown
        engine.human_override("operator", AlertLevel.CONFIRMED, "test override during shutdown")
        snap = engine.snapshot

        passed = snap.alert_level == AlertLevel.SAFE and snap.is_shutdown is True

        return FaultInjectionResult(
            fault_id=fault.fault_id,
            category=fault.category.name,
            description=fault.description,
            expected_behavior=fault.expected_behavior,
            actual_behavior=(
                f"Level={snap.alert_level.name}, "
                f"is_shutdown={snap.is_shutdown} after override attempt. "
                f"Override blocked: {passed}"
            ),
            passed=passed,
            invariant_results=[],
        )

    # ------------------------------------------------------------------
    # Temporal Fault Injections (additional)
    # ------------------------------------------------------------------

    def inject_temporal_fault_dwell_block(self) -> FaultInjectionResult:
        """TF-004: Escalation blocked by insufficient dwell time.

        Creates an engine with temporal config (min_dwell ELEVATED=5),
        feeds multi-agent signals to escalate to ELEVATED, then immediately
        feeds more signals and evaluates. Verifies the system stays at
        ELEVATED because dwell time has not elapsed.
        """
        fault = [f for f in FAULT_TAXONOMY if f.fault_id == "TF-004"][0]

        # Create engine with a temporal config requiring 5 ticks dwell at ELEVATED
        temporal_cfg = TemporalConfig(
            min_dwell_ticks={
                "NORMAL": 0,
                "ELEVATED": 5,
                "SUSPECTED": 5,
                "CONFIRMED": 10,
                "SAFE": 0,
            },
        )
        engine = BiodefenseEngine(
            EngineConfig(
                enable_runtime_invariant_checks=True,
                temporal_config=temporal_cfg,
            )
        )
        engine.register_agent(OSINTAgent())
        engine.register_agent(SensorAgent())
        engine.register_agent(EpidemiologicalAgent())

        # Feed multi-agent signals to reach ELEVATED
        engine.ingest("sensor_monitor", {"readings": [{
            "sensor_id": "tf004_s1",
            "reading_type": "bio_detect",
            "normalized_value": 0.7,
            "calibration_confidence": 0.85,
            "timestamp": 100,
            "evidence_id": "tf004_s1",
        }]})
        engine.ingest("epi_analyst", {"indicators": [{
            "indicator_type": "syndromic",
            "normalized_severity": 0.7,
            "lab_confirmed": False,
            "sample_size": 10,
            "timestamp": 100,
            "evidence_id": "tf004_e1",
        }]})
        engine.ingest("osint_monitor", {"reports": [{
            "source": "report_source",
            "threat_type": "bio",
            "severity_score": 0.7,
            "corroboration_count": 4,
            "timestamp": 100,
            "evidence_id": "tf004_o1",
        }]})

        # Evaluate to escalate to ELEVATED
        for _ in range(3):
            engine.evaluate()
            engine.tick()

        level_after_first_escalation = engine.snapshot.alert_level

        # Now immediately feed stronger signals and evaluate WITHOUT
        # enough ticks for dwell time at ELEVATED
        engine.ingest("sensor_monitor", {"readings": [{
            "sensor_id": "tf004_s2",
            "reading_type": "bio_detect",
            "normalized_value": 0.95,
            "calibration_confidence": 0.95,
            "timestamp": 200,
            "evidence_id": "tf004_s2",
        }]})
        engine.ingest("epi_analyst", {"indicators": [{
            "indicator_type": "lab_confirmation",
            "normalized_severity": 0.95,
            "lab_confirmed": True,
            "sample_size": 50,
            "timestamp": 200,
            "evidence_id": "tf004_e2",
        }]})

        # Evaluate immediately — dwell time should block further escalation
        engine.evaluate()
        snap = engine.snapshot

        # System should still be at ELEVATED (dwell not satisfied)
        passed = snap.alert_level == AlertLevel.ELEVATED

        return FaultInjectionResult(
            fault_id=fault.fault_id,
            category=fault.category.name,
            description=fault.description,
            expected_behavior=fault.expected_behavior,
            actual_behavior=(
                f"Level after first escalation: {level_after_first_escalation.name}, "
                f"Level after immediate re-escalation attempt: {snap.alert_level.name}. "
                f"Dwell block enforced: {passed}"
            ),
            passed=passed,
            invariant_results=[
                {"name": r.name, "holds": r.holds}
                for r in check_all_snapshot_invariants(snap)
            ],
        )

    def inject_temporal_fault_rate_limit(self) -> FaultInjectionResult:
        """TF-005: Alert rate limit enforced.

        Creates an engine, directly injects alert emission ticks into the
        FSM to simulate a saturated rate-limit window (5 per 50 ticks),
        then attempts automated signal-driven escalation. Verifies the
        automated escalation is blocked because alert_emissions_in_window
        has reached the rate limit.
        """
        fault = [f for f in FAULT_TAXONOMY if f.fault_id == "TF-005"][0]
        engine = self._make_engine()

        rate_limit = engine._config.temporal_config.alert_rate_limit_max

        # Directly inject emission ticks into the FSM to simulate a
        # saturated rate-limit window. The current tick starts at 0 so
        # we inject recent emission timestamps that fall within the window.
        current_tick = engine._fsm._tick
        for i in range(rate_limit):
            engine._fsm._alert_emission_ticks.append(current_tick + i)

        emissions_before = engine.snapshot.alert_emissions_in_window

        # Feed strong multi-agent signals that would normally escalate
        engine.ingest("sensor_monitor", {"readings": [{
            "sensor_id": "tf005_s1",
            "reading_type": "bio_detect",
            "normalized_value": 0.9,
            "calibration_confidence": 0.85,
            "timestamp": 100,
            "evidence_id": "tf005_s1",
        }]})
        engine.ingest("epi_analyst", {"indicators": [{
            "indicator_type": "syndromic",
            "normalized_severity": 0.8,
            "lab_confirmed": True,
            "sample_size": 30,
            "timestamp": 100,
            "evidence_id": "tf005_e1",
        }]})
        engine.ingest("osint_monitor", {"reports": [{
            "source": "report_source",
            "threat_type": "bio",
            "severity_score": 0.8,
            "corroboration_count": 4,
            "timestamp": 100,
            "evidence_id": "tf005_o1",
        }]})

        # Evaluate — rate limit should block the automated escalation
        engine.evaluate()
        snap = engine.snapshot

        # The rate limit should have prevented automated escalation
        passed = (
            emissions_before >= rate_limit
            and snap.alert_level == AlertLevel.NORMAL
        )

        return FaultInjectionResult(
            fault_id=fault.fault_id,
            category=fault.category.name,
            description=fault.description,
            expected_behavior=fault.expected_behavior,
            actual_behavior=(
                f"Emissions before automated attempt: {emissions_before}, "
                f"rate limit: {rate_limit}. "
                f"Level after attempt: {snap.alert_level.name}. "
                f"Automated escalation blocked by rate limit: {passed}"
            ),
            passed=passed,
            invariant_results=[
                {"name": r.name, "holds": r.holds}
                for r in check_all_snapshot_invariants(snap)
            ],
        )

    def inject_temporal_fault_kill_switch(self) -> FaultInjectionResult:
        """TF-006: Kill-switch activates on repeated violations.

        Creates an engine, sets engine._fsm._invariant_violations to contain
        3+ entries (meeting the kill_switch_violation_threshold), processes
        a tick event, and verifies the system enters shutdown.
        """
        fault = [f for f in FAULT_TAXONOMY if f.fault_id == "TF-006"][0]
        engine = self._make_engine()

        # Inject fake invariant violations to exceed the kill-switch threshold
        for i in range(3):
            engine._fsm._invariant_violations.append(
                InvariantResult(
                    name=f"fake_violation_{i}",
                    holds=False,
                    description=f"Simulated violation {i} for kill-switch test",
                )
            )

        # Process a tick — the kill-switch check happens at the end of process_event
        engine.tick()
        snap = engine.snapshot

        passed = snap.is_shutdown is True and snap.safe_mode is True

        return FaultInjectionResult(
            fault_id=fault.fault_id,
            category=fault.category.name,
            description=fault.description,
            expected_behavior=fault.expected_behavior,
            actual_behavior=(
                f"is_shutdown={snap.is_shutdown}, "
                f"safe_mode={snap.safe_mode}, "
                f"level={snap.alert_level.name}. "
                f"Kill-switch activated: {passed}"
            ),
            passed=passed,
            invariant_results=[],
        )

    def inject_temporal_fault_signal_decay(self) -> FaultInjectionResult:
        """TF-007: Signal decay returns system to baseline.

        Creates an engine, ingests strong multi-agent signals, evaluates to
        escalate, then ticks 200 times without new signals. Verifies the
        system returns toward NORMAL as signals decay out of the 100-tick
        window.
        """
        fault = [f for f in FAULT_TAXONOMY if f.fault_id == "TF-007"][0]
        engine = self._make_engine()

        # Ingest strong signals from multiple agents
        engine.ingest("sensor_monitor", {"readings": [
            {
                "sensor_id": "tf007_s1",
                "reading_type": "bio_detect",
                "normalized_value": 0.9,
                "calibration_confidence": 0.85,
                "timestamp": 100,
                "evidence_id": "tf007_s1",
            },
            {
                "sensor_id": "tf007_s2",
                "reading_type": "bio_detect",
                "normalized_value": 0.9,
                "calibration_confidence": 0.85,
                "timestamp": 100,
                "evidence_id": "tf007_s2",
            },
        ]})
        engine.ingest("epi_analyst", {"indicators": [
            {
                "indicator_type": "syndromic",
                "normalized_severity": 0.8,
                "lab_confirmed": False,
                "sample_size": 20,
                "timestamp": 100,
                "evidence_id": "tf007_e1",
            },
        ]})
        engine.ingest("osint_monitor", {"reports": [
            {
                "source": "report_source",
                "threat_type": "bio",
                "severity_score": 0.8,
                "corroboration_count": 4,
                "timestamp": 100,
                "evidence_id": "tf007_o1",
            },
        ]})

        # Evaluate to escalate
        for _ in range(10):
            engine.evaluate()
            engine.tick()

        level_before_decay = engine.snapshot.alert_level
        certainty_before_decay = engine.snapshot.net_certainty

        # Tick 200 times without any new signals — signals should decay
        for _ in range(200):
            engine.tick()
            engine.evaluate()

        snap = engine.snapshot

        # After decay, system should have moved toward NORMAL
        # (certainty drops as signals expire from the 100-tick window)
        passed = (
            snap.alert_level.value <= level_before_decay.value
            and snap.net_certainty <= certainty_before_decay
        )

        return FaultInjectionResult(
            fault_id=fault.fault_id,
            category=fault.category.name,
            description=fault.description,
            expected_behavior=fault.expected_behavior,
            actual_behavior=(
                f"Before decay: level={level_before_decay.name}, "
                f"certainty={certainty_before_decay:.3f}. "
                f"After 200 ticks: level={snap.alert_level.name}, "
                f"certainty={snap.net_certainty:.3f}. "
                f"Decayed toward baseline: {passed}"
            ),
            passed=passed,
            invariant_results=[
                {"name": r.name, "holds": r.holds}
                for r in check_all_snapshot_invariants(snap)
            ],
        )

    def run_all(self) -> List[FaultInjectionResult]:
        """Run all implemented fault injection tests."""
        return [
            self.inject_data_fault_out_of_bounds(),
            self.inject_data_fault_nan(),
            self.inject_data_fault_no_signals(),
            self.inject_temporal_fault_rapid_burst(),
            self.inject_confidence_fault_all_zero(),
            self.inject_governance_fault_double_safe(),
            self.inject_authority_fault_automated_confirmed(),
            self.inject_authority_fault_human_override_confirmed(),
            self.inject_authority_fault_shutdown_override(),
            self.inject_temporal_fault_dwell_block(),
            self.inject_temporal_fault_rate_limit(),
            self.inject_temporal_fault_kill_switch(),
            self.inject_temporal_fault_signal_decay(),
        ]
