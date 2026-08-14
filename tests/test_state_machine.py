"""
Tests for the state machine — the deterministic decision core.
"""

import pytest
from src.types import AlertLevel, AgentVote, BoundedSignal
from src.state_machine import (
    BiodefenseStateMachine,
    Event,
    EVENT_SIGNALS_RECEIVED,
    EVENT_VOTE_COMPLETE,
    EVENT_SAFE_MODE_ENTER,
    EVENT_SAFE_MODE_EXIT,
    EVENT_HUMAN_OVERRIDE,
    EVENT_TICK,
    TransitionThresholds,
    aggregate_certainty,
    compute_agreement,
)


# ---------------------------------------------------------------------------
# Certainty Aggregation
# ---------------------------------------------------------------------------

class TestAggregateCertainty:
    def test_no_signals(self):
        certainty, uncertainty = aggregate_certainty([])
        assert certainty == 0.0
        assert uncertainty == 1.0

    def test_single_confident_signal(self):
        sig = BoundedSignal("a", "t", 0.8, 1.0, 0)
        certainty, uncertainty = aggregate_certainty([sig])
        assert certainty == 0.8
        assert uncertainty == 0.0

    def test_zero_confidence_signals(self):
        sig = BoundedSignal("a", "t", 0.8, 0.0, 0)
        certainty, uncertainty = aggregate_certainty([sig])
        assert certainty == 0.0
        assert uncertainty == 1.0

    def test_mixed_confidence(self):
        sig1 = BoundedSignal("a", "t", 0.9, 0.8, 0)
        sig2 = BoundedSignal("b", "t", 0.1, 0.2, 0)
        certainty, uncertainty = aggregate_certainty([sig1, sig2])
        # weighted: (0.9*0.8 + 0.1*0.2) / (0.8 + 0.2) = 0.74 / 1.0 = 0.74
        assert abs(certainty - 0.74) < 0.001
        # mean_confidence = (0.8+0.2)/2 = 0.5, uncertainty = 0.5
        assert abs(uncertainty - 0.5) < 0.001


# ---------------------------------------------------------------------------
# Agreement Computation
# ---------------------------------------------------------------------------

class TestComputeAgreement:
    def test_no_votes(self):
        ratio, level = compute_agreement([])
        assert ratio == 0.0
        assert level is None

    def test_unanimous_votes(self):
        votes = [
            AgentVote("a", AlertLevel.ELEVATED, (), 0.8, "test"),
            AgentVote("b", AlertLevel.ELEVATED, (), 0.7, "test"),
        ]
        ratio, level = compute_agreement(votes)
        assert level == AlertLevel.ELEVATED
        assert ratio == 1.0

    def test_split_votes(self):
        votes = [
            AgentVote("a", AlertLevel.ELEVATED, (), 0.5, "test"),
            AgentVote("b", AlertLevel.NORMAL, (), 0.5, "test"),
        ]
        ratio, level = compute_agreement(votes)
        assert ratio == 0.5


# ---------------------------------------------------------------------------
# State Machine Transitions
# ---------------------------------------------------------------------------

class TestStateMachine:
    def test_initial_state(self):
        fsm = BiodefenseStateMachine()
        snap = fsm.snapshot
        assert snap.alert_level == AlertLevel.NORMAL
        assert snap.safe_mode is False
        assert snap.net_certainty == 0.0
        assert snap.uncertainty == 1.0

    def test_safe_mode_enter_exit(self):
        fsm = BiodefenseStateMachine()
        fsm.process_event(Event(event_type=EVENT_SAFE_MODE_ENTER))
        snap = fsm.snapshot
        assert snap.alert_level == AlertLevel.SAFE
        assert snap.safe_mode is True

        fsm.process_event(Event(event_type=EVENT_SAFE_MODE_EXIT))
        snap = fsm.snapshot
        assert snap.alert_level == AlertLevel.NORMAL
        assert snap.safe_mode is False

    def test_safe_mode_idempotent(self):
        fsm = BiodefenseStateMachine()
        fsm.process_event(Event(event_type=EVENT_SAFE_MODE_ENTER))
        fsm.process_event(Event(event_type=EVENT_SAFE_MODE_ENTER))
        snap = fsm.snapshot
        assert snap.alert_level == AlertLevel.SAFE

    def test_signals_update_certainty(self):
        fsm = BiodefenseStateMachine()
        sig = BoundedSignal("agent_a", "test", 0.7, 0.9, 100)
        event = Event(
            event_type=EVENT_SIGNALS_RECEIVED,
            signals=(sig,),
        )
        fsm.process_event(event)
        snap = fsm.snapshot
        assert snap.net_certainty > 0
        assert snap.uncertainty < 1.0

    def test_no_escalation_without_quorum(self):
        fsm = BiodefenseStateMachine()

        # Single agent vote
        sig = BoundedSignal("agent_a", "test", 0.8, 0.9, 100)
        fsm.process_event(Event(
            event_type=EVENT_SIGNALS_RECEIVED,
            signals=(sig,),
        ))

        vote = AgentVote("agent_a", AlertLevel.ELEVATED, (sig.signal_id,), 0.9, "test")
        fsm.process_event(Event(
            event_type=EVENT_VOTE_COMPLETE,
            votes=(vote,),
        ))

        # Should NOT escalate — only one agent
        snap = fsm.snapshot
        assert snap.alert_level == AlertLevel.NORMAL

    def test_escalation_with_quorum(self):
        fsm = BiodefenseStateMachine()

        # Two agents provide signals
        sig1 = BoundedSignal("agent_a", "test", 0.7, 0.9, 100)
        sig2 = BoundedSignal("agent_b", "test", 0.6, 0.8, 101)
        fsm.process_event(Event(
            event_type=EVENT_SIGNALS_RECEIVED,
            signals=(sig1, sig2),
        ))

        # Two agents vote for ELEVATED
        vote1 = AgentVote("agent_a", AlertLevel.ELEVATED,
                          (sig1.signal_id,), 0.8, "test")
        vote2 = AgentVote("agent_b", AlertLevel.ELEVATED,
                          (sig2.signal_id,), 0.7, "test")
        fsm.process_event(Event(
            event_type=EVENT_VOTE_COMPLETE,
            votes=(vote1, vote2),
        ))

        snap = fsm.snapshot
        assert snap.alert_level == AlertLevel.ELEVATED

    def test_safe_mode_blocks_automated_escalation(self):
        fsm = BiodefenseStateMachine()
        fsm.process_event(Event(event_type=EVENT_SAFE_MODE_ENTER))

        # Try to escalate with quorum
        sig1 = BoundedSignal("agent_a", "test", 0.9, 0.9, 100)
        sig2 = BoundedSignal("agent_b", "test", 0.9, 0.9, 101)
        fsm.process_event(Event(
            event_type=EVENT_SIGNALS_RECEIVED,
            signals=(sig1, sig2),
        ))

        vote1 = AgentVote("agent_a", AlertLevel.ELEVATED,
                          (sig1.signal_id,), 0.9, "test")
        vote2 = AgentVote("agent_b", AlertLevel.ELEVATED,
                          (sig2.signal_id,), 0.9, "test")
        fsm.process_event(Event(
            event_type=EVENT_VOTE_COMPLETE,
            votes=(vote1, vote2),
        ))

        snap = fsm.snapshot
        assert snap.alert_level == AlertLevel.SAFE

    def test_no_level_skipping(self):
        fsm = BiodefenseStateMachine()

        # Even with high certainty, cannot skip to CONFIRMED
        sig1 = BoundedSignal("agent_a", "test", 1.0, 1.0, 100)
        sig2 = BoundedSignal("agent_b", "test", 1.0, 1.0, 101)
        fsm.process_event(Event(
            event_type=EVENT_SIGNALS_RECEIVED,
            signals=(sig1, sig2),
        ))

        vote1 = AgentVote("agent_a", AlertLevel.CONFIRMED,
                          (sig1.signal_id,), 1.0, "test")
        vote2 = AgentVote("agent_b", AlertLevel.CONFIRMED,
                          (sig2.signal_id,), 1.0, "test")
        fsm.process_event(Event(
            event_type=EVENT_VOTE_COMPLETE,
            votes=(vote1, vote2),
        ))

        # Should only go to ELEVATED (one step from NORMAL)
        snap = fsm.snapshot
        assert snap.alert_level == AlertLevel.ELEVATED

    def test_unknown_event_is_noop(self):
        fsm = BiodefenseStateMachine()
        before = fsm.snapshot
        fsm.process_event(Event(event_type="TOTALLY_UNKNOWN"))
        after = fsm.snapshot
        assert before.alert_level == after.alert_level

    def test_transition_log_records_changes(self):
        fsm = BiodefenseStateMachine()
        fsm.process_event(Event(event_type=EVENT_SAFE_MODE_ENTER))
        assert len(fsm.transition_log) >= 1
        assert fsm.transition_log[-1].to_state == AlertLevel.SAFE
