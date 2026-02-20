"""Tests for event schemas — immutability, defaults, serialization."""

import pytest
from bare.schemas.events import (
    AgentRole,
    Alert,
    AnomalyReport,
    AuditEntry,
    EpiAssessment,
    RawSignal,
    SeverityLevel,
    SignalSource,
    ThreatAssessment,
    ThreatCategory,
)


class TestRawSignal:
    def test_default_construction(self):
        s = RawSignal()
        assert s.source == SignalSource.SIMULATED
        assert s.raw_score == 0.0
        assert s.signal_id  # UUID generated

    def test_immutable(self):
        s = RawSignal()
        with pytest.raises(AttributeError):
            s.raw_score = 0.5  # type: ignore[misc]

    def test_unique_ids(self):
        s1 = RawSignal()
        s2 = RawSignal()
        assert s1.signal_id != s2.signal_id

    def test_custom_fields(self):
        s = RawSignal(
            source=SignalSource.WASTEWATER,
            region="US-NY",
            pathogen_hint="anthrax",
            raw_score=0.85,
        )
        assert s.source == SignalSource.WASTEWATER
        assert s.region == "US-NY"
        assert s.raw_score == 0.85


class TestAnomalyReport:
    def test_default_construction(self):
        r = AnomalyReport()
        assert r.originating_agent == AgentRole.OSINT_INGESTION
        assert r.z_score == 0.0

    def test_immutable(self):
        r = AnomalyReport()
        with pytest.raises(AttributeError):
            r.z_score = 3.0  # type: ignore[misc]


class TestEpiAssessment:
    def test_defaults(self):
        a = EpiAssessment()
        assert a.false_positive_prob == 1.0
        assert a.confidence == 0.0

    def test_custom(self):
        a = EpiAssessment(
            pathogen="ebola",
            r0_estimate=2.5,
            confidence=0.8,
            false_positive_prob=0.2,
        )
        assert a.r0_estimate == 2.5


class TestThreatAssessment:
    def test_defaults(self):
        t = ThreatAssessment()
        assert t.category == ThreatCategory.UNDETERMINED
        assert t.severity == SeverityLevel.WATCH

    def test_escalation_flag(self):
        t = ThreatAssessment(requires_human_escalation=True)
        assert t.requires_human_escalation is True


class TestAlert:
    def test_default_requires_human(self):
        a = Alert()
        assert a.requires_human_confirmation is True

    def test_audit_chain(self):
        a = Alert(audit_chain=("id1", "id2", "id3"))
        assert len(a.audit_chain) == 3
