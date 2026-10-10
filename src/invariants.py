"""
Formal Invariant Definitions for the Biodefense Alerting & Response Engine.

These invariants are LAWS. They must hold in ALL executions, including
adversarial ones. Each invariant is:
  1. Formally stated as a predicate over SystemSnapshot
  2. Machine-checkable at runtime
  3. Traced to the TLA+ specification

Violation of any invariant is a system failure — not a warning, not a
degradation. A failure.

TRACEABILITY: spec/biodefense.tla :: Invariants
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from .types import (
    AgentVote,
    AlertLevel,
    BoundedSignal,
    CausalExplanation,
    HumanAuthorityPolicy,
    SystemSnapshot,
    TemporalConfig,
    TransitionRecord,
)


# ---------------------------------------------------------------------------
# Invariant Result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InvariantResult:
    """Result of checking a single invariant."""
    name: str
    holds: bool
    description: str
    violation_detail: str = ""


# ---------------------------------------------------------------------------
# INV-1: No Single Agent Escalation
# ---------------------------------------------------------------------------
# Formal statement:
#   ∀ transition T from level L to level L' where L' > L:
#     |{a ∈ contributing_agents(T)}| ≥ QUORUM_SIZE
#     ∧ |{distinct source_agent(s) : s ∈ triggering_signals(T)}| ≥ 2
#
# English: No single signal, model, or agent can independently cause
# escalation. At least QUORUM_SIZE agents must contribute, and signals
# must come from at least 2 distinct sources.

QUORUM_SIZE = 2  # Minimum agents required for any escalation


def inv_no_single_agent_escalation(
    record: TransitionRecord,
    human_override: bool = False,
) -> InvariantResult:
    """INV-1: Escalation requires multi-agent quorum."""
    name = "INV-1:NoSingleAgentEscalation"

    # Human overrides and governance transitions bypass quorum
    if human_override:
        return InvariantResult(name=name, holds=True,
                               description="Human override — quorum bypassed by design")

    # De-escalation and lateral transitions are unrestricted
    if record.to_state <= record.from_state:
        return InvariantResult(name=name, holds=True,
                               description="Not an escalation — invariant trivially holds")

    explanation = record.explanation
    n_agents = len(explanation.contributing_agents)
    distinct_sources = len(set(explanation.triggering_signals))

    if n_agents < QUORUM_SIZE:
        return InvariantResult(
            name=name, holds=False,
            description="Escalation requires quorum",
            violation_detail=(
                f"Only {n_agents} contributing agents; "
                f"minimum required is {QUORUM_SIZE}"
            ),
        )

    if distinct_sources < 2:
        return InvariantResult(
            name=name, holds=False,
            description="Escalation requires multi-source signals",
            violation_detail=(
                f"Only {distinct_sources} distinct signal source(s); "
                f"minimum required is 2"
            ),
        )

    return InvariantResult(
        name=name, holds=True,
        description=f"Quorum of {n_agents} agents, {distinct_sources} distinct signals",
    )


# ---------------------------------------------------------------------------
# INV-2: Severity Monotonic with Net Certainty
# ---------------------------------------------------------------------------
# Formal statement:
#   ∀ snapshots S1, S2 where S2.tick = S1.tick + 1:
#     S2.alert_level > S1.alert_level → S2.net_certainty > S1.net_certainty
#     ∧ S2.alert_level < S1.alert_level → S2.net_certainty < S1.net_certainty
#
# English: The system can only escalate if certainty increased, and can
# only de-escalate if certainty decreased. No arbitrary jumps.

def inv_severity_monotonic_with_certainty(
    before: SystemSnapshot,
    after: SystemSnapshot,
    human_override: bool = False,
) -> InvariantResult:
    """INV-2: Alert level changes must be justified by certainty changes."""
    name = "INV-2:SeverityMonotonicWithCertainty"

    # Human overrides and governance transitions bypass certainty monotonicity
    if human_override:
        return InvariantResult(
            name=name, holds=True,
            description="Human/governance override — certainty check bypassed",
        )

    if after.alert_level > before.alert_level:
        if after.net_certainty <= before.net_certainty:
            return InvariantResult(
                name=name, holds=False,
                description="Escalation without certainty increase",
                violation_detail=(
                    f"Level {before.alert_level.name} -> {after.alert_level.name} "
                    f"but certainty {before.net_certainty} -> {after.net_certainty}"
                ),
            )

    if after.alert_level < before.alert_level:
        # Exception: transition TO safe mode is governance, not certainty-driven
        if after.alert_level != AlertLevel.SAFE:
            if after.net_certainty >= before.net_certainty:
                return InvariantResult(
                    name=name, holds=False,
                    description="De-escalation without certainty decrease",
                    violation_detail=(
                        f"Level {before.alert_level.name} -> {after.alert_level.name} "
                        f"but certainty {before.net_certainty} -> {after.net_certainty}"
                    ),
                )

    return InvariantResult(
        name=name, holds=True,
        description="Severity consistent with certainty direction",
    )


# ---------------------------------------------------------------------------
# INV-3: Safe Mode Disables Automated Escalation
# ---------------------------------------------------------------------------
# Formal statement:
#   ∀ snapshots S where S.safe_mode = true:
#     ∀ transitions T from S:
#       T.to_state ≤ S.alert_level
#
# English: When safe mode is active, the system CANNOT automatically
# escalate. It can de-escalate or hold steady. Only human override
# can escalate from safe mode.

def inv_safe_mode_blocks_escalation(
    before: SystemSnapshot,
    after: SystemSnapshot,
    human_override: bool = False,
) -> InvariantResult:
    """INV-3: Safe mode prevents automated escalation."""
    name = "INV-3:SafeModeBlocksEscalation"

    if not before.safe_mode:
        return InvariantResult(
            name=name, holds=True,
            description="Safe mode not active — invariant trivially holds",
        )

    if after.alert_level > before.alert_level and not human_override:
        return InvariantResult(
            name=name, holds=False,
            description="Automated escalation while in safe mode",
            violation_detail=(
                f"Safe mode active but escalated "
                f"{before.alert_level.name} -> {after.alert_level.name} "
                f"without human override"
            ),
        )

    return InvariantResult(
        name=name, holds=True,
        description="Safe mode respected",
    )


# ---------------------------------------------------------------------------
# INV-4: Uncertainty Always Surfaced
# ---------------------------------------------------------------------------
# Formal statement:
#   ∀ snapshots S: S.uncertainty ≥ 0
#   ∧ ∀ transitions T: T.explanation.uncertainty_estimate ≥ 0
#   ∧ ∀ signals sig where sig.confidence < 1.0:
#       snapshot_containing(sig).uncertainty > 0
#
# English: Uncertainty is a first-class value. It is NEVER hidden, masked,
# or defaulted to zero when signals have imperfect confidence.

def inv_uncertainty_surfaced(
    snapshot: SystemSnapshot,
) -> InvariantResult:
    """INV-4: Uncertainty is explicitly tracked and never masked."""
    name = "INV-4:UncertaintySurfaced"

    # Uncertainty must be non-negative
    if snapshot.uncertainty < 0:
        return InvariantResult(
            name=name, holds=False,
            description="Negative uncertainty is meaningless",
            violation_detail=f"uncertainty = {snapshot.uncertainty}",
        )

    # If any pending signal has confidence < 1.0, system uncertainty must be > 0
    has_imperfect_signal = any(
        s.confidence < 1.0 for s in snapshot.pending_signals
    )
    if has_imperfect_signal and snapshot.uncertainty == 0.0:
        return InvariantResult(
            name=name, holds=False,
            description="Uncertainty masked despite imperfect signals",
            violation_detail=(
                "At least one signal has confidence < 1.0 but "
                "system uncertainty is reported as 0.0"
            ),
        )

    return InvariantResult(
        name=name, holds=True,
        description=f"Uncertainty = {snapshot.uncertainty:.4f}, explicitly tracked",
    )


# ---------------------------------------------------------------------------
# INV-5: Deterministic Replay
# ---------------------------------------------------------------------------
# Formal statement:
#   ∀ input sequences I:
#     decide(I) = decide(I)
#
# English: Given identical inputs (same signals in same order), the system
# produces identical decisions. No hidden randomness, no time-of-day
# dependencies, no external state leakage.
#
# Implementation note: This invariant is enforced structurally — the
# decision function uses only its explicit inputs. It is tested by
# replaying recorded input sequences and comparing snapshot_ids.

def inv_deterministic_replay(
    inputs: Sequence[BoundedSignal],
    run1_snapshot_id: str,
    run2_snapshot_id: str,
) -> InvariantResult:
    """INV-5: Identical inputs produce identical decisions."""
    name = "INV-5:DeterministicReplay"

    if run1_snapshot_id != run2_snapshot_id:
        return InvariantResult(
            name=name, holds=False,
            description="Non-deterministic behavior detected",
            violation_detail=(
                f"Same inputs produced different snapshots: "
                f"{run1_snapshot_id} vs {run2_snapshot_id}"
            ),
        )

    return InvariantResult(
        name=name, holds=True,
        description="Deterministic replay confirmed",
    )


# ---------------------------------------------------------------------------
# INV-6: Full Causal Explanation Required
# ---------------------------------------------------------------------------
# Formal statement:
#   ∀ transitions T where T.from_state ≠ T.to_state:
#     T.explanation ≠ ⊥
#     ∧ T.explanation.triggering_signals ≠ ∅
#     ∧ T.explanation.human_readable_summary ≠ ""
#
# English: Every state change must carry a complete causal explanation.
# Humans must never be surprised by alerts.

def inv_causal_explanation_required(
    record: TransitionRecord,
) -> InvariantResult:
    """INV-6: Every state change has a full causal explanation."""
    name = "INV-6:CausalExplanationRequired"

    if record.from_state == record.to_state:
        return InvariantResult(
            name=name, holds=True,
            description="No state change — no explanation needed",
        )

    exp = record.explanation
    if not exp.triggering_signals:
        return InvariantResult(
            name=name, holds=False,
            description="State change without triggering signals",
            violation_detail="CausalExplanation.triggering_signals is empty",
        )

    if not exp.human_readable_summary:
        return InvariantResult(
            name=name, holds=False,
            description="State change without human-readable explanation",
            violation_detail="CausalExplanation.human_readable_summary is empty",
        )

    if not exp.contributing_agents:
        return InvariantResult(
            name=name, holds=False,
            description="State change without contributing agents",
            violation_detail="CausalExplanation.contributing_agents is empty",
        )

    return InvariantResult(
        name=name, holds=True,
        description="Full causal explanation present",
    )


# ---------------------------------------------------------------------------
# INV-7: Signal Bounds
# ---------------------------------------------------------------------------
# Formal statement:
#   ∀ signals S in system:
#     0.0 ≤ S.value ≤ 1.0 ∧ 0.0 ≤ S.confidence ≤ 1.0
#
# English: All signals are bounded. Unbounded signals are faults.

def inv_signal_bounds(
    snapshot: SystemSnapshot,
) -> InvariantResult:
    """INV-7: All signals are within [0.0, 1.0]."""
    name = "INV-7:SignalBounds"

    for sig in snapshot.pending_signals:
        if not (0.0 <= sig.value <= 1.0):
            return InvariantResult(
                name=name, holds=False,
                description="Signal value out of bounds",
                violation_detail=(
                    f"Signal {sig.signal_id} from {sig.source_agent}: "
                    f"value={sig.value}"
                ),
            )
        if not (0.0 <= sig.confidence <= 1.0):
            return InvariantResult(
                name=name, holds=False,
                description="Signal confidence out of bounds",
                violation_detail=(
                    f"Signal {sig.signal_id} from {sig.source_agent}: "
                    f"confidence={sig.confidence}"
                ),
            )

    return InvariantResult(
        name=name, holds=True,
        description=f"All {len(snapshot.pending_signals)} signals within bounds",
    )


# ---------------------------------------------------------------------------
# INV-8: No Level Skipping
# ---------------------------------------------------------------------------
# Formal statement:
#   ∀ transitions T:
#     |T.to_state - T.from_state| ≤ 1
#     EXCEPT when T.to_state = SAFE (governance override)
#
# English: The system cannot jump from NORMAL to CONFIRMED. It must
# traverse each intermediate level. Exception: entering SAFE mode
# is always allowed as a governance action.

def inv_no_level_skipping(
    record: TransitionRecord,
    human_override: bool = False,
) -> InvariantResult:
    """INV-8: Alert level changes by at most one step (except SAFE)."""
    name = "INV-8:NoLevelSkipping"

    # Human overrides may skip levels — they represent external confirmation
    if human_override:
        return InvariantResult(
            name=name, holds=True,
            description="Human override — level skipping allowed by design",
        )

    if record.to_state == AlertLevel.SAFE:
        return InvariantResult(
            name=name, holds=True,
            description="Transition to SAFE — always allowed",
        )

    if record.from_state == AlertLevel.SAFE:
        # Exiting safe mode: can only go to NORMAL
        if record.to_state != AlertLevel.NORMAL:
            return InvariantResult(
                name=name, holds=False,
                description="Exiting SAFE must go to NORMAL",
                violation_detail=(
                    f"SAFE -> {record.to_state.name} skips levels"
                ),
            )
        return InvariantResult(
            name=name, holds=True,
            description="SAFE -> NORMAL transition",
        )

    delta = abs(record.to_state.value - record.from_state.value)
    if delta > 1:
        return InvariantResult(
            name=name, holds=False,
            description="Alert level jumped more than one step",
            violation_detail=(
                f"{record.from_state.name} -> {record.to_state.name} "
                f"(delta={delta})"
            ),
        )

    return InvariantResult(
        name=name, holds=True,
        description=f"{record.from_state.name} -> {record.to_state.name}",
    )


# ---------------------------------------------------------------------------
# INV-9: Automated Actions Bounded by Human Authority
# ---------------------------------------------------------------------------
# Formal statement:
#   ∀ automated transitions T (not human_override):
#     T.to_state ≤ policy.max_automated_level
#     ∧ (policy.confirmed_requires_human ∧ T.to_state = CONFIRMED)
#       → T is human_override
#
# English: Automated logic cannot escalate beyond the configured
# authority ceiling. CONFIRMED level requires explicit human
# confirmation unless the policy is explicitly relaxed.

DEFAULT_AUTHORITY_POLICY = HumanAuthorityPolicy()


def inv_authority_bounds(
    record: TransitionRecord,
    human_override: bool = False,
    policy: HumanAuthorityPolicy = DEFAULT_AUTHORITY_POLICY,
) -> InvariantResult:
    """INV-9: Automated escalation respects human authority bounds."""
    name = "INV-9:AuthorityBounds"

    # De-escalation and lateral transitions are unrestricted
    if record.to_state <= record.from_state:
        return InvariantResult(
            name=name, holds=True,
            description="Not an escalation — authority check trivially holds",
        )

    # Human overrides are not bounded by automation limits
    if human_override:
        return InvariantResult(
            name=name, holds=True,
            description="Human override — authority check bypassed",
        )

    # Check: automated escalation must not exceed max_automated_level
    if record.to_state > policy.max_automated_level:
        return InvariantResult(
            name=name, holds=False,
            description="Automated escalation exceeds authority ceiling",
            violation_detail=(
                f"Automated transition to {record.to_state.name} exceeds "
                f"max_automated_level={policy.max_automated_level.name}"
            ),
        )

    # Check: CONFIRMED requires human if policy says so
    if (policy.confirmed_requires_human
            and record.to_state == AlertLevel.CONFIRMED):
        return InvariantResult(
            name=name, holds=False,
            description="CONFIRMED requires human authorization",
            violation_detail=(
                "Policy requires human confirmation for CONFIRMED level "
                "but this is an automated transition"
            ),
        )

    return InvariantResult(
        name=name, holds=True,
        description=f"Automated escalation within authority bounds",
    )


# ---------------------------------------------------------------------------
# INV-10: Minimum Dwell Time
# ---------------------------------------------------------------------------
# Formal statement:
#   ∀ transitions T where T.to_state > T.from_state:
#     before.ticks_in_current_level ≥ min_dwell(T.from_state)
#
# English: The system must remain at a level for a minimum number of
# ticks before it can escalate further. This prevents panic under burst noise.

DEFAULT_TEMPORAL_CONFIG = TemporalConfig()


def inv_min_dwell_time(
    before: SystemSnapshot,
    record: TransitionRecord,
    human_override: bool = False,
    config: TemporalConfig = DEFAULT_TEMPORAL_CONFIG,
) -> InvariantResult:
    """INV-10: Minimum dwell time before escalation."""
    name = "INV-10:MinDwellTime"

    # Only applies to escalation
    if record.to_state <= record.from_state:
        return InvariantResult(
            name=name, holds=True,
            description="Not an escalation — dwell check trivially holds",
        )

    # Human overrides bypass dwell time
    if human_override:
        return InvariantResult(
            name=name, holds=True,
            description="Human override — dwell check bypassed",
        )

    # Governance transitions (to/from SAFE) bypass dwell time
    if record.from_state == AlertLevel.SAFE or record.to_state == AlertLevel.SAFE:
        return InvariantResult(
            name=name, holds=True,
            description="Governance transition — dwell check bypassed",
        )

    level_name = record.from_state.name
    min_dwell = config.min_dwell_ticks.get(level_name, 0)

    if before.ticks_in_current_level < min_dwell:
        return InvariantResult(
            name=name, holds=False,
            description="Escalation before minimum dwell time",
            violation_detail=(
                f"At {level_name} for {before.ticks_in_current_level} ticks, "
                f"minimum required is {min_dwell}"
            ),
        )

    return InvariantResult(
        name=name, holds=True,
        description=(
            f"Dwell time {before.ticks_in_current_level} >= "
            f"min {min_dwell} for {level_name}"
        ),
    )


# ---------------------------------------------------------------------------
# INV-11: Alert Rate Limit
# ---------------------------------------------------------------------------
# Formal statement:
#   ∀ windows W of length alert_rate_limit_window ticks:
#     |{transitions T in W where T.from_state ≠ T.to_state}|
#       ≤ alert_rate_limit_max
#
# English: The system cannot emit more than N alerts within a given
# time window. This prevents alert flooding under adversarial input.

def inv_alert_rate_limit(
    snapshot: SystemSnapshot,
    config: TemporalConfig = DEFAULT_TEMPORAL_CONFIG,
) -> InvariantResult:
    """INV-11: Alert emission rate is bounded."""
    name = "INV-11:AlertRateLimit"

    if snapshot.alert_emissions_in_window > config.alert_rate_limit_max:
        return InvariantResult(
            name=name, holds=False,
            description="Alert rate limit exceeded",
            violation_detail=(
                f"{snapshot.alert_emissions_in_window} alerts in window, "
                f"limit is {config.alert_rate_limit_max}"
            ),
        )

    return InvariantResult(
        name=name, holds=True,
        description=(
            f"{snapshot.alert_emissions_in_window} alerts in window "
            f"(limit {config.alert_rate_limit_max})"
        ),
    )


# ---------------------------------------------------------------------------
# Invariant Registry — all invariants in one place
# ---------------------------------------------------------------------------

ALL_INVARIANT_NAMES = (
    "INV-1:NoSingleAgentEscalation",
    "INV-2:SeverityMonotonicWithCertainty",
    "INV-3:SafeModeBlocksEscalation",
    "INV-4:UncertaintySurfaced",
    "INV-5:DeterministicReplay",
    "INV-6:CausalExplanationRequired",
    "INV-7:SignalBounds",
    "INV-8:NoLevelSkipping",
    "INV-9:AuthorityBounds",
    "INV-10:MinDwellTime",
    "INV-11:AlertRateLimit",
)


def check_all_snapshot_invariants(snapshot: SystemSnapshot) -> List[InvariantResult]:
    """Check all invariants that apply to a single snapshot."""
    return [
        inv_uncertainty_surfaced(snapshot),
        inv_signal_bounds(snapshot),
        inv_alert_rate_limit(snapshot),
    ]


def check_all_transition_invariants(
    before: SystemSnapshot,
    after: SystemSnapshot,
    record: TransitionRecord,
    human_override: bool = False,
) -> List[InvariantResult]:
    """Check all invariants that apply to a state transition."""
    return [
        inv_no_single_agent_escalation(record, human_override),
        inv_severity_monotonic_with_certainty(before, after, human_override),
        inv_safe_mode_blocks_escalation(before, after, human_override),
        inv_uncertainty_surfaced(after),
        inv_causal_explanation_required(record),
        inv_signal_bounds(after),
        inv_no_level_skipping(record, human_override),
        inv_authority_bounds(record, human_override),
        inv_min_dwell_time(before, record, human_override),
        inv_alert_rate_limit(after),
    ]
