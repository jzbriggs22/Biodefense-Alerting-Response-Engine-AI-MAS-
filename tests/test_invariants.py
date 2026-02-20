"""
Tests for formal invariant definitions.

These tests verify that the invariant checking functions correctly
identify violations and pass valid states.
"""

import pytest
from src.types import (
    AlertLevel, BoundedSignal, CausalExplanation,
    SystemSnapshot, TransitionRecord,
)
from src.invariants import (
    inv_no_single_agent_escalation,
    inv_severity_monotonic_with_certainty,
    inv_safe_mode_blocks_escalation,
    inv_uncertainty_surfaced,
    inv_deterministic_replay,
    inv_causal_explanation_required,
    inv_signal_bounds,
    inv_no_level_skipping,
    check_all_snapshot_invariants,
    QUORUM_SIZE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_signal(agent="agent_a", value=0.5, confidence=0.7, ts=100):
    return BoundedSignal(
        source_agent=agent,
        signal_type="test",
        value=value,
        confidence=confidence,
        timestamp_monotonic=ts,
    )


def make_snapshot(
    level=AlertLevel.NORMAL,
    safe_mode=False,
    signals=(),
    certainty=0.0,
    uncertainty=1.0,
    tick=0,
):
    return SystemSnapshot(
        tick=tick,
        alert_level=level,
        safe_mode=safe_mode,
        pending_signals=signals,
        active_agents=frozenset(),
        last_explanation=None,
        net_certainty=certainty,
        uncertainty=uncertainty,
    )


def make_explanation(
    from_level=AlertLevel.NORMAL,
    to_level=AlertLevel.ELEVATED,
    agents=("agent_a", "agent_b"),
    signals=("sig_1", "sig_2"),
    certainty=0.5,
    uncertainty=0.3,
):
    return CausalExplanation(
        triggering_signals=signals,
        contributing_agents=agents,
        quorum_met=len(agents) >= QUORUM_SIZE,
        net_certainty=certainty,
        uncertainty_estimate=uncertainty,
        human_readable_summary="Test transition",
        from_level=from_level,
        to_level=to_level,
    )


def make_record(
    from_level=AlertLevel.NORMAL,
    to_level=AlertLevel.ELEVATED,
    agents=("agent_a", "agent_b"),
    signals=("sig_1", "sig_2"),
):
    explanation = make_explanation(from_level, to_level, agents, signals)
    return TransitionRecord(
        tick=0,
        from_state=from_level,
        to_state=to_level,
        explanation=explanation,
        snapshot_before="before",
        snapshot_after="after",
        invariants_checked=(),
        all_invariants_passed=True,
    )


# ---------------------------------------------------------------------------
# INV-1: No Single Agent Escalation
# ---------------------------------------------------------------------------

class TestNoSingleAgentEscalation:
    def test_quorum_met(self):
        record = make_record(agents=("a", "b"), signals=("s1", "s2"))
        result = inv_no_single_agent_escalation(record)
        assert result.holds

    def test_single_agent_fails(self):
        record = make_record(agents=("a",), signals=("s1", "s2"))
        result = inv_no_single_agent_escalation(record)
        assert not result.holds

    def test_single_signal_fails(self):
        record = make_record(agents=("a", "b"), signals=("s1",))
        result = inv_no_single_agent_escalation(record)
        assert not result.holds

    def test_deescalation_trivially_holds(self):
        record = make_record(
            from_level=AlertLevel.ELEVATED,
            to_level=AlertLevel.NORMAL,
            agents=("a",),
            signals=("s1",),
        )
        result = inv_no_single_agent_escalation(record)
        assert result.holds

    def test_lateral_trivially_holds(self):
        record = make_record(
            from_level=AlertLevel.ELEVATED,
            to_level=AlertLevel.ELEVATED,
            agents=("a",),
            signals=("s1",),
        )
        result = inv_no_single_agent_escalation(record)
        assert result.holds


# ---------------------------------------------------------------------------
# INV-2: Severity Monotonic with Certainty
# ---------------------------------------------------------------------------

class TestSeverityMonotonic:
    def test_escalation_with_increasing_certainty(self):
        before = make_snapshot(level=AlertLevel.NORMAL, certainty=0.2)
        after = make_snapshot(level=AlertLevel.ELEVATED, certainty=0.5)
        result = inv_severity_monotonic_with_certainty(before, after)
        assert result.holds

    def test_escalation_without_certainty_increase_fails(self):
        before = make_snapshot(level=AlertLevel.NORMAL, certainty=0.5)
        after = make_snapshot(level=AlertLevel.ELEVATED, certainty=0.5)
        result = inv_severity_monotonic_with_certainty(before, after)
        assert not result.holds

    def test_deescalation_with_decreasing_certainty(self):
        before = make_snapshot(level=AlertLevel.ELEVATED, certainty=0.5)
        after = make_snapshot(level=AlertLevel.NORMAL, certainty=0.2)
        result = inv_severity_monotonic_with_certainty(before, after)
        assert result.holds

    def test_to_safe_mode_always_allowed(self):
        before = make_snapshot(level=AlertLevel.ELEVATED, certainty=0.5)
        after = make_snapshot(level=AlertLevel.SAFE, certainty=0.5)
        result = inv_severity_monotonic_with_certainty(before, after)
        assert result.holds


# ---------------------------------------------------------------------------
# INV-3: Safe Mode Blocks Escalation
# ---------------------------------------------------------------------------

class TestSafeModeBlocks:
    def test_safe_mode_blocks_escalation(self):
        before = make_snapshot(level=AlertLevel.SAFE, safe_mode=True)
        after = make_snapshot(level=AlertLevel.ELEVATED, safe_mode=True)
        result = inv_safe_mode_blocks_escalation(before, after)
        assert not result.holds

    def test_safe_mode_allows_human_override(self):
        before = make_snapshot(level=AlertLevel.SAFE, safe_mode=True)
        after = make_snapshot(level=AlertLevel.ELEVATED, safe_mode=True)
        result = inv_safe_mode_blocks_escalation(
            before, after, human_override=True
        )
        assert result.holds

    def test_not_in_safe_mode_trivially_holds(self):
        before = make_snapshot(level=AlertLevel.NORMAL, safe_mode=False)
        after = make_snapshot(level=AlertLevel.ELEVATED, safe_mode=False)
        result = inv_safe_mode_blocks_escalation(before, after)
        assert result.holds


# ---------------------------------------------------------------------------
# INV-4: Uncertainty Surfaced
# ---------------------------------------------------------------------------

class TestUncertaintySurfaced:
    def test_uncertainty_with_imperfect_signals(self):
        sig = make_signal(confidence=0.7)
        snap = make_snapshot(signals=(sig,), uncertainty=0.3)
        result = inv_uncertainty_surfaced(snap)
        assert result.holds

    def test_zero_uncertainty_with_imperfect_signals_fails(self):
        sig = make_signal(confidence=0.7)
        snap = make_snapshot(signals=(sig,), uncertainty=0.0)
        result = inv_uncertainty_surfaced(snap)
        assert not result.holds

    def test_zero_uncertainty_with_perfect_signals_holds(self):
        sig = make_signal(confidence=1.0)
        snap = make_snapshot(signals=(sig,), uncertainty=0.0)
        result = inv_uncertainty_surfaced(snap)
        assert result.holds

    def test_negative_uncertainty_fails(self):
        snap = make_snapshot(uncertainty=-0.1)
        result = inv_uncertainty_surfaced(snap)
        assert not result.holds


# ---------------------------------------------------------------------------
# INV-5: Deterministic Replay
# ---------------------------------------------------------------------------

class TestDeterministicReplay:
    def test_same_snapshots_pass(self):
        result = inv_deterministic_replay([], "abc123", "abc123")
        assert result.holds

    def test_different_snapshots_fail(self):
        result = inv_deterministic_replay([], "abc123", "def456")
        assert not result.holds


# ---------------------------------------------------------------------------
# INV-6: Causal Explanation Required
# ---------------------------------------------------------------------------

class TestCausalExplanation:
    def test_state_change_with_explanation(self):
        record = make_record()
        result = inv_causal_explanation_required(record)
        assert result.holds

    def test_no_state_change_trivially_holds(self):
        record = make_record(
            from_level=AlertLevel.NORMAL,
            to_level=AlertLevel.NORMAL,
        )
        result = inv_causal_explanation_required(record)
        assert result.holds


# ---------------------------------------------------------------------------
# INV-7: Signal Bounds
# ---------------------------------------------------------------------------

class TestSignalBounds:
    def test_valid_signals(self):
        sig = make_signal(value=0.5, confidence=0.8)
        snap = make_snapshot(signals=(sig,))
        result = inv_signal_bounds(snap)
        assert result.holds

    def test_empty_signals(self):
        snap = make_snapshot(signals=())
        result = inv_signal_bounds(snap)
        assert result.holds

    def test_out_of_bounds_value_rejected_at_construction(self):
        with pytest.raises(ValueError):
            make_signal(value=1.5)


# ---------------------------------------------------------------------------
# INV-8: No Level Skipping
# ---------------------------------------------------------------------------

class TestNoLevelSkipping:
    def test_one_step_escalation(self):
        record = make_record(
            from_level=AlertLevel.NORMAL,
            to_level=AlertLevel.ELEVATED,
        )
        result = inv_no_level_skipping(record)
        assert result.holds

    def test_two_step_escalation_fails(self):
        record = make_record(
            from_level=AlertLevel.NORMAL,
            to_level=AlertLevel.SUSPECTED,
        )
        result = inv_no_level_skipping(record)
        assert not result.holds

    def test_to_safe_always_allowed(self):
        record = make_record(
            from_level=AlertLevel.CONFIRMED,
            to_level=AlertLevel.SAFE,
        )
        result = inv_no_level_skipping(record)
        assert result.holds

    def test_from_safe_must_go_to_normal(self):
        record = make_record(
            from_level=AlertLevel.SAFE,
            to_level=AlertLevel.ELEVATED,
        )
        result = inv_no_level_skipping(record)
        assert not result.holds

    def test_from_safe_to_normal_allowed(self):
        record = make_record(
            from_level=AlertLevel.SAFE,
            to_level=AlertLevel.NORMAL,
        )
        result = inv_no_level_skipping(record)
        assert result.holds
