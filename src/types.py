"""
Core types for the Biodefense Alerting & Response Engine.

All types are immutable. No type in this module has side effects.
These types form the vocabulary shared between the formal specification (TLA+)
and the implementation. Changes here require re-verification.

TRACEABILITY: spec/biodefense.tla :: TypeInvariant
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import FrozenSet, Optional, Tuple


# ---------------------------------------------------------------------------
# Alert Levels — ordered by severity
# ---------------------------------------------------------------------------

class AlertLevel(enum.IntEnum):
    """
    System-wide alert levels. The integer ordering is the severity ordering.
    SAFE < NORMAL < ELEVATED < SUSPECTED < CONFIRMED.

    TRACEABILITY: spec/biodefense.tla :: AlertLevels
    """
    SAFE = 0       # Safe mode — automated escalation disabled
    NORMAL = 1     # Baseline — no threat indicators
    ELEVATED = 2   # Anomaly detected — watching
    SUSPECTED = 3  # Corroborated anomaly — human review required
    CONFIRMED = 4  # Multi-source confirmation — response activated


# ---------------------------------------------------------------------------
# Bounded Signal — the ONLY interface between ML/heuristic and decisions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BoundedSignal:
    """
    A bounded, typed signal emitted by an agent.

    - `value` is clamped to [0.0, 1.0]. Values outside this range
      are evidence of a fault, not valid input.
    - `confidence` is clamped to [0.0, 1.0].
    - `source_agent` identifies the emitting agent.
    - `signal_id` is a content-addressed hash for deterministic replay.

    TRACEABILITY: spec/biodefense.tla :: Signal
    """
    source_agent: str
    signal_type: str
    value: float
    confidence: float
    timestamp_monotonic: int  # Monotonic clock ticks, not wall clock
    evidence_ids: FrozenSet[str] = field(default_factory=frozenset)
    metadata: str = ""  # JSON-encoded, opaque to decision logic

    def __post_init__(self):
        # Enforce bounds — these are NOT soft constraints
        if not (0.0 <= self.value <= 1.0):
            raise ValueError(
                f"Signal value {self.value} out of bounds [0.0, 1.0]. "
                f"Source: {self.source_agent}, type: {self.signal_type}"
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"Signal confidence {self.confidence} out of bounds [0.0, 1.0]. "
                f"Source: {self.source_agent}, type: {self.signal_type}"
            )
        if not self.source_agent:
            raise ValueError("source_agent must be non-empty")
        if not self.signal_type:
            raise ValueError("signal_type must be non-empty")

    @property
    def signal_id(self) -> str:
        """Content-addressed ID for deterministic replay."""
        content = json.dumps({
            "source_agent": self.source_agent,
            "signal_type": self.signal_type,
            "value": self.value,
            "confidence": self.confidence,
            "timestamp_monotonic": self.timestamp_monotonic,
            "evidence_ids": sorted(self.evidence_ids),
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Causal Explanation — required for every transition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CausalExplanation:
    """
    A structured explanation for why a state transition occurred.
    Every transition MUST have one. This is not optional.

    TRACEABILITY: spec/biodefense.tla :: CausalExplanation
    """
    triggering_signals: Tuple[str, ...]  # signal_ids that contributed
    contributing_agents: Tuple[str, ...]  # agents that voted
    quorum_met: bool
    net_certainty: float  # Aggregated certainty that triggered the transition
    uncertainty_estimate: float  # Explicit uncertainty — never hidden
    human_readable_summary: str
    from_level: AlertLevel
    to_level: AlertLevel

    def __post_init__(self):
        if not self.triggering_signals:
            raise ValueError("CausalExplanation must reference at least one signal")
        if not self.human_readable_summary:
            raise ValueError("CausalExplanation must have a human-readable summary")
        if not (0.0 <= self.uncertainty_estimate <= 1.0):
            raise ValueError(
                f"Uncertainty estimate {self.uncertainty_estimate} out of bounds"
            )


# ---------------------------------------------------------------------------
# System Snapshot — the full observable state at a point in time
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SystemSnapshot:
    """
    Complete observable state of the system at one logical tick.
    Used for deterministic replay and invariant checking.

    TRACEABILITY: spec/biodefense.tla :: SystemState
    """
    tick: int  # Monotonic logical clock
    alert_level: AlertLevel
    safe_mode: bool
    pending_signals: Tuple[BoundedSignal, ...]
    active_agents: FrozenSet[str]
    last_explanation: Optional[CausalExplanation]
    net_certainty: float  # Current aggregated certainty
    uncertainty: float  # Current explicit uncertainty

    @property
    def snapshot_id(self) -> str:
        """Content-addressed ID for the entire system state."""
        content = json.dumps({
            "tick": self.tick,
            "alert_level": self.alert_level.value,
            "safe_mode": self.safe_mode,
            "signal_ids": [s.signal_id for s in self.pending_signals],
            "active_agents": sorted(self.active_agents),
            "net_certainty": self.net_certainty,
            "uncertainty": self.uncertainty,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Transition Record — immutable audit log entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TransitionRecord:
    """
    Immutable record of a state transition. Append-only audit log.

    TRACEABILITY: spec/biodefense.tla :: TransitionLog
    """
    tick: int
    from_state: AlertLevel
    to_state: AlertLevel
    explanation: CausalExplanation
    snapshot_before: str  # snapshot_id
    snapshot_after: str   # snapshot_id
    invariants_checked: Tuple[str, ...]  # Names of invariants verified
    all_invariants_passed: bool


# ---------------------------------------------------------------------------
# Agent Vote — structured quorum input
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AgentVote:
    """
    A vote from an agent regarding a proposed state transition.

    TRACEABILITY: spec/biodefense.tla :: AgentVote
    """
    agent_id: str
    proposed_level: AlertLevel
    signal_ids: Tuple[str, ...]  # Signals motivating this vote
    confidence: float
    rationale: str

    def __post_init__(self):
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Vote confidence {self.confidence} out of bounds")
        if not self.agent_id:
            raise ValueError("agent_id must be non-empty")
