"""
Finite State Machine for the Biodefense Alerting & Response Engine.

This module contains ONLY deterministic decision logic. No ML, no
heuristics, no randomness. The state machine consumes BoundedSignals
and produces state transitions that are fully explainable.

Design principle: THINKING is separated from DECIDING.
  - Thinking: ML models, statistical inference, heuristics → produce BoundedSignals
  - Deciding: This module → consumes BoundedSignals, produces transitions

ML outputs may only influence transitions via BoundedSignals. There is no
back door.

TRACEABILITY: spec/biodefense.tla :: StateMachine
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .invariants import (
    QUORUM_SIZE,
    check_all_transition_invariants,
    InvariantResult,
)
from .types import (
    AgentVote,
    AlertLevel,
    BoundedSignal,
    CausalExplanation,
    SystemSnapshot,
    TransitionRecord,
)


# ---------------------------------------------------------------------------
# Transition Guards — explicit thresholds
# ---------------------------------------------------------------------------
# These thresholds are the ONLY numbers that control escalation behavior.
# They are not tunable at runtime. Changing them requires re-verification.
#
# TRACEABILITY: spec/biodefense.tla :: Thresholds

@dataclass(frozen=True)
class TransitionThresholds:
    """
    Explicit thresholds for state transitions.

    All values are in [0.0, 1.0] and represent net certainty levels.
    """
    # Minimum net certainty to escalate TO each level
    escalate_to_elevated: float = 0.3
    escalate_to_suspected: float = 0.55
    escalate_to_confirmed: float = 0.8

    # Maximum net certainty to de-escalate FROM each level
    deescalate_from_elevated: float = 0.15
    deescalate_from_suspected: float = 0.35
    deescalate_from_confirmed: float = 0.55

    # Hysteresis gap: escalate threshold - deescalate threshold
    # This prevents oscillation. The gap is structural, not tunable.
    #
    # ELEVATED:  escalate=0.30, deescalate=0.15, gap=0.15
    # SUSPECTED: escalate=0.55, deescalate=0.35, gap=0.20
    # CONFIRMED: escalate=0.80, deescalate=0.55, gap=0.25
    #
    # The gap INCREASES with severity. This is intentional:
    # the higher the alert, the more certainty decay is needed
    # before de-escalation.

    # Minimum number of confirming signals for escalation
    min_confirming_signals: int = 2

    # Minimum distinct agents for quorum
    min_quorum_agents: int = QUORUM_SIZE

    # Minimum confidence-weighted agreement among voting agents
    min_agreement_ratio: float = 0.6

    def __post_init__(self):
        # Verify hysteresis gaps are positive
        assert self.escalate_to_elevated > self.deescalate_from_elevated, \
            "No hysteresis gap for ELEVATED"
        assert self.escalate_to_suspected > self.deescalate_from_suspected, \
            "No hysteresis gap for SUSPECTED"
        assert self.escalate_to_confirmed > self.deescalate_from_confirmed, \
            "No hysteresis gap for CONFIRMED"

        # Verify monotonicity of thresholds
        assert (self.escalate_to_elevated
                < self.escalate_to_suspected
                < self.escalate_to_confirmed), \
            "Escalation thresholds must be strictly increasing"


# Default thresholds — immutable
DEFAULT_THRESHOLDS = TransitionThresholds()


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Event:
    """
    An event that the state machine processes.

    TRACEABILITY: spec/biodefense.tla :: Events
    """
    event_type: str  # One of the EVENT_* constants below
    signals: Tuple[BoundedSignal, ...] = ()
    votes: Tuple[AgentVote, ...] = ()
    human_override: bool = False
    safe_mode_requested: bool = False
    metadata: str = ""

# Event types
EVENT_SIGNALS_RECEIVED = "SIGNALS_RECEIVED"
EVENT_VOTE_COMPLETE = "VOTE_COMPLETE"
EVENT_SAFE_MODE_ENTER = "SAFE_MODE_ENTER"
EVENT_SAFE_MODE_EXIT = "SAFE_MODE_EXIT"
EVENT_HUMAN_OVERRIDE = "HUMAN_OVERRIDE"
EVENT_TICK = "TICK"  # Periodic re-evaluation with no new signals


# ---------------------------------------------------------------------------
# Certainty Aggregation — deterministic, bounded
# ---------------------------------------------------------------------------

def aggregate_certainty(signals: Sequence[BoundedSignal]) -> Tuple[float, float]:
    """
    Aggregate signals into (net_certainty, uncertainty).

    Method: confidence-weighted mean of signal values.
    This is deliberately simple. Complexity here is a risk.

    Returns:
        (net_certainty, uncertainty) both in [0.0, 1.0]
    """
    if not signals:
        return (0.0, 1.0)  # No signals → zero certainty, maximum uncertainty

    total_weight = sum(s.confidence for s in signals)
    if total_weight == 0.0:
        return (0.0, 1.0)  # All signals have zero confidence

    weighted_sum = sum(s.value * s.confidence for s in signals)
    net_certainty = weighted_sum / total_weight

    # Uncertainty: inverse of mean confidence, scaled
    mean_confidence = total_weight / len(signals)
    uncertainty = 1.0 - mean_confidence

    # Clamp to bounds
    net_certainty = max(0.0, min(1.0, net_certainty))
    uncertainty = max(0.0, min(1.0, uncertainty))

    return (net_certainty, uncertainty)


def compute_agreement(votes: Sequence[AgentVote]) -> Tuple[float, Optional[AlertLevel]]:
    """
    Compute agreement ratio among agent votes.

    Returns:
        (agreement_ratio, majority_level)
        agreement_ratio: fraction of confidence-weighted votes for the majority level
        majority_level: the level with the most weighted support, or None if no votes
    """
    if not votes:
        return (0.0, None)

    # Tally confidence-weighted votes per level
    level_weight: Dict[AlertLevel, float] = {}
    for vote in votes:
        level_weight[vote.proposed_level] = (
            level_weight.get(vote.proposed_level, 0.0) + vote.confidence
        )

    total_weight = sum(level_weight.values())
    if total_weight == 0.0:
        return (0.0, None)

    majority_level = max(level_weight, key=lambda k: level_weight[k])
    agreement_ratio = level_weight[majority_level] / total_weight

    return (agreement_ratio, majority_level)


# ---------------------------------------------------------------------------
# State Machine Core
# ---------------------------------------------------------------------------

class BiodefenseStateMachine:
    """
    Deterministic finite state machine for biodefense alert management.

    States: SAFE, NORMAL, ELEVATED, SUSPECTED, CONFIRMED
    Events: SIGNALS_RECEIVED, VOTE_COMPLETE, SAFE_MODE_*, HUMAN_OVERRIDE, TICK
    Transitions: Guarded by thresholds and invariants

    This class is the ONLY place where state transitions happen.
    All transitions are logged. All transitions are invariant-checked.

    TRACEABILITY: spec/biodefense.tla :: StateMachine
    """

    def __init__(
        self,
        thresholds: TransitionThresholds = DEFAULT_THRESHOLDS,
        initial_level: AlertLevel = AlertLevel.NORMAL,
    ):
        self._thresholds = thresholds
        self._tick = 0
        self._alert_level = initial_level
        self._safe_mode = False
        self._pending_signals: List[BoundedSignal] = []
        self._active_agents: frozenset = frozenset()
        self._net_certainty = 0.0
        self._uncertainty = 1.0
        self._certainty_at_level_entry = 0.0  # Certainty when current level was entered
        self._last_explanation: Optional[CausalExplanation] = None
        self._transition_log: List[TransitionRecord] = []
        self._invariant_violations: List[InvariantResult] = []

    # -- Public read-only accessors --

    @property
    def snapshot(self) -> SystemSnapshot:
        """Current system state as an immutable snapshot."""
        return SystemSnapshot(
            tick=self._tick,
            alert_level=self._alert_level,
            safe_mode=self._safe_mode,
            pending_signals=tuple(self._pending_signals),
            active_agents=self._active_agents,
            last_explanation=self._last_explanation,
            net_certainty=self._net_certainty,
            uncertainty=self._uncertainty,
        )

    @property
    def transition_log(self) -> Tuple[TransitionRecord, ...]:
        return tuple(self._transition_log)

    @property
    def invariant_violations(self) -> Tuple[InvariantResult, ...]:
        return tuple(self._invariant_violations)

    # -- Core transition logic --

    def process_event(self, event: Event) -> SystemSnapshot:
        """
        Process an event and potentially transition state.

        This is the ONLY entry point for state changes.
        Returns the new system snapshot.

        TRACEABILITY: spec/biodefense.tla :: Next
        """
        before = self.snapshot

        if event.event_type == EVENT_SAFE_MODE_ENTER:
            self._enter_safe_mode(before, event)
        elif event.event_type == EVENT_SAFE_MODE_EXIT:
            self._exit_safe_mode(before, event)
        elif event.event_type == EVENT_SIGNALS_RECEIVED:
            self._process_signals(before, event)
        elif event.event_type == EVENT_VOTE_COMPLETE:
            self._process_votes(before, event)
        elif event.event_type == EVENT_HUMAN_OVERRIDE:
            self._process_human_override(before, event)
        elif event.event_type == EVENT_TICK:
            self._process_tick(before, event)
        else:
            # Unknown event type — do nothing. This is deliberate:
            # unknown events are not errors, they are no-ops.
            pass

        self._tick += 1
        return self.snapshot

    def _enter_safe_mode(self, before: SystemSnapshot, event: Event) -> None:
        """Transition to SAFE mode."""
        if self._safe_mode:
            return  # Already in safe mode — idempotent

        old_level = self._alert_level
        self._safe_mode = True
        self._alert_level = AlertLevel.SAFE

        explanation = CausalExplanation(
            triggering_signals=("governance:safe_mode_enter",),
            contributing_agents=("governance",),
            quorum_met=True,  # Governance actions don't require quorum
            net_certainty=self._net_certainty,
            uncertainty_estimate=self._uncertainty,
            human_readable_summary="Safe mode activated — automated escalation disabled",
            from_level=old_level,
            to_level=AlertLevel.SAFE,
        )
        self._last_explanation = explanation
        self._record_transition(before, explanation)

    def _exit_safe_mode(self, before: SystemSnapshot, event: Event) -> None:
        """Exit SAFE mode, returning to NORMAL."""
        if not self._safe_mode:
            return

        self._safe_mode = False
        self._alert_level = AlertLevel.NORMAL
        self._net_certainty = 0.0
        self._uncertainty = 1.0
        self._pending_signals.clear()

        explanation = CausalExplanation(
            triggering_signals=("governance:safe_mode_exit",),
            contributing_agents=("governance",),
            quorum_met=True,
            net_certainty=0.0,
            uncertainty_estimate=1.0,
            human_readable_summary="Safe mode deactivated — returning to NORMAL baseline",
            from_level=AlertLevel.SAFE,
            to_level=AlertLevel.NORMAL,
        )
        self._last_explanation = explanation
        self._record_transition(before, explanation)

    def _process_signals(self, before: SystemSnapshot, event: Event) -> None:
        """Ingest new signals and update certainty. Does NOT transition state."""
        for sig in event.signals:
            self._pending_signals.append(sig)

        # Update agent registry
        new_agents = frozenset(s.source_agent for s in event.signals)
        self._active_agents = self._active_agents | new_agents

        # Recompute certainty from all pending signals
        self._net_certainty, self._uncertainty = aggregate_certainty(
            self._pending_signals
        )

    def _process_votes(self, before: SystemSnapshot, event: Event) -> None:
        """Process agent votes and potentially transition state."""
        if not event.votes:
            return

        agreement_ratio, majority_level = compute_agreement(event.votes)

        if majority_level is None:
            return

        # Check if transition is warranted
        proposed_level = self._evaluate_transition(
            current_level=self._alert_level,
            net_certainty=self._net_certainty,
            agreement_ratio=agreement_ratio,
            majority_level=majority_level,
            n_signals=len(self._pending_signals),
            n_agents=len(set(v.agent_id for v in event.votes)),
        )

        if proposed_level == self._alert_level:
            return  # No transition

        # Collect signal IDs from votes
        all_signal_ids: List[str] = []
        for vote in event.votes:
            all_signal_ids.extend(vote.signal_ids)

        # Ensure we have signal IDs even if votes didn't reference them
        if not all_signal_ids:
            all_signal_ids = [s.signal_id for s in self._pending_signals[-2:]]

        contributing = tuple(sorted(set(v.agent_id for v in event.votes)))

        explanation = CausalExplanation(
            triggering_signals=tuple(all_signal_ids),
            contributing_agents=contributing,
            quorum_met=len(contributing) >= QUORUM_SIZE,
            net_certainty=self._net_certainty,
            uncertainty_estimate=self._uncertainty,
            human_readable_summary=self._build_summary(
                before.alert_level, proposed_level, event.votes
            ),
            from_level=self._alert_level,
            to_level=proposed_level,
        )

        self._alert_level = proposed_level
        self._last_explanation = explanation
        self._record_transition(before, explanation)

    def _process_human_override(self, before: SystemSnapshot, event: Event) -> None:
        """Process a human override — can bypass some guards."""
        if not event.votes:
            return

        # Human overrides still require explanation but bypass quorum
        vote = event.votes[0]

        all_signal_ids = list(vote.signal_ids) if vote.signal_ids else []
        if not all_signal_ids:
            all_signal_ids = [s.signal_id for s in self._pending_signals[-1:]]
        if not all_signal_ids:
            all_signal_ids = ["human_override:manual"]

        explanation = CausalExplanation(
            triggering_signals=tuple(all_signal_ids),
            contributing_agents=(vote.agent_id,),
            quorum_met=True,  # Human override counts as quorum
            net_certainty=self._net_certainty,
            uncertainty_estimate=self._uncertainty,
            human_readable_summary=f"Human override: {vote.rationale}",
            from_level=self._alert_level,
            to_level=vote.proposed_level,
        )

        self._alert_level = vote.proposed_level
        if vote.proposed_level == AlertLevel.SAFE:
            self._safe_mode = True
        self._last_explanation = explanation
        self._record_transition(before, explanation, human_override=True)

    def _process_tick(self, before: SystemSnapshot, event: Event) -> None:
        """Periodic re-evaluation — recalculate certainty, check for decay."""
        # Signal decay: remove signals older than decay window
        # (This uses monotonic timestamps, not wall clock)
        if self._pending_signals:
            current_time = self._pending_signals[-1].timestamp_monotonic
            decay_window = 100  # ticks
            self._pending_signals = [
                s for s in self._pending_signals
                if current_time - s.timestamp_monotonic <= decay_window
            ]
            self._net_certainty, self._uncertainty = aggregate_certainty(
                self._pending_signals
            )

    def _evaluate_transition(
        self,
        current_level: AlertLevel,
        net_certainty: float,
        agreement_ratio: float,
        majority_level: AlertLevel,
        n_signals: int,
        n_agents: int,
    ) -> AlertLevel:
        """
        Evaluate whether a transition is warranted.

        Returns the new level (may be same as current).

        Guards:
          - Certainty must cross threshold
          - Agreement must meet minimum
          - Quorum must be met
          - Signal count must meet minimum
          - No level skipping
          - Safe mode blocks escalation

        TRACEABILITY: spec/biodefense.tla :: EvaluateTransition
        """
        t = self._thresholds

        # Safe mode: no automated escalation
        if self._safe_mode:
            return current_level

        # Check if we should escalate one level
        if majority_level > current_level:
            # Can only go up one step
            target = AlertLevel(current_level.value + 1)

            # Check all guards
            if n_agents < t.min_quorum_agents:
                return current_level
            if n_signals < t.min_confirming_signals:
                return current_level
            if agreement_ratio < t.min_agreement_ratio:
                return current_level

            # Certainty must have INCREASED since the current level was entered.
            # This prevents re-escalation on stale evidence (INV-2).
            if net_certainty <= self._certainty_at_level_entry:
                return current_level

            # Check certainty threshold for target level
            threshold = {
                AlertLevel.ELEVATED: t.escalate_to_elevated,
                AlertLevel.SUSPECTED: t.escalate_to_suspected,
                AlertLevel.CONFIRMED: t.escalate_to_confirmed,
            }.get(target)

            if threshold is None:
                return current_level

            if net_certainty >= threshold:
                return target

        # Check if we should de-escalate one level
        if current_level > AlertLevel.NORMAL:
            threshold = {
                AlertLevel.ELEVATED: t.deescalate_from_elevated,
                AlertLevel.SUSPECTED: t.deescalate_from_suspected,
                AlertLevel.CONFIRMED: t.deescalate_from_confirmed,
            }.get(current_level)

            if threshold is not None and net_certainty <= threshold:
                return AlertLevel(current_level.value - 1)

        return current_level

    def _record_transition(
        self,
        before: SystemSnapshot,
        explanation: CausalExplanation,
        human_override: bool = False,
    ) -> None:
        """Record a transition and check invariants."""
        after = self.snapshot

        # For INV-2 (severity monotonic with certainty), we compare against
        # the certainty at the time the PREVIOUS level was established, not
        # the certainty at the start of the current event. This is because
        # certainty updates during signal ingestion and level changes during
        # evaluate — they happen in different events.
        level_entry_snapshot = SystemSnapshot(
            tick=before.tick,
            alert_level=before.alert_level,
            safe_mode=before.safe_mode,
            pending_signals=before.pending_signals,
            active_agents=before.active_agents,
            last_explanation=before.last_explanation,
            net_certainty=self._certainty_at_level_entry,
            uncertainty=before.uncertainty,
        )

        # Check ALL invariants
        results = check_all_transition_invariants(
            before=level_entry_snapshot,
            after=after,
            record=TransitionRecord(
                tick=self._tick,
                from_state=explanation.from_level,
                to_state=explanation.to_level,
                explanation=explanation,
                snapshot_before=before.snapshot_id,
                snapshot_after=after.snapshot_id,
                invariants_checked=(),
                all_invariants_passed=True,
            ),
            human_override=human_override,
        )

        all_passed = all(r.holds for r in results)
        violations = [r for r in results if not r.holds]

        record = TransitionRecord(
            tick=self._tick,
            from_state=explanation.from_level,
            to_state=explanation.to_level,
            explanation=explanation,
            snapshot_before=before.snapshot_id,
            snapshot_after=after.snapshot_id,
            invariants_checked=tuple(r.name for r in results),
            all_invariants_passed=all_passed,
        )

        self._transition_log.append(record)

        # Update level-entry certainty after recording
        self._certainty_at_level_entry = self._net_certainty

        if violations:
            self._invariant_violations.extend(violations)
            # In a production system, invariant violations would trigger
            # immediate safe mode and operator notification.

    def _build_summary(
        self,
        from_level: AlertLevel,
        to_level: AlertLevel,
        votes: Sequence[AgentVote],
    ) -> str:
        """Build a human-readable summary of a transition."""
        direction = "Escalation" if to_level > from_level else "De-escalation"
        agents = ", ".join(sorted(set(v.agent_id for v in votes)))
        rationales = "; ".join(v.rationale for v in votes if v.rationale)

        return (
            f"{direction}: {from_level.name} → {to_level.name}. "
            f"Contributing agents: {agents}. "
            f"Net certainty: {self._net_certainty:.3f}, "
            f"uncertainty: {self._uncertainty:.3f}. "
            f"Rationale: {rationales}"
        )
