"""
Integration tests for the biodefense engine.
"""

import pytest
from src.engine import BiodefenseEngine, EngineConfig
from src.agents.osint_agent import OSINTAgent
from src.agents.sensor_agent import SensorAgent
from src.agents.epi_agent import EpidemiologicalAgent
from src.types import AlertLevel


def make_engine():
    engine = BiodefenseEngine()
    engine.register_agent(OSINTAgent())
    engine.register_agent(SensorAgent())
    engine.register_agent(EpidemiologicalAgent())
    return engine


class TestEngineIntegration:
    def test_starts_at_normal(self):
        engine = make_engine()
        assert engine.snapshot.alert_level == AlertLevel.NORMAL

    def test_osint_alone_cannot_reach_confirmed(self):
        engine = make_engine()
        # Flood with high-severity OSINT
        for i in range(20):
            engine.ingest("osint_monitor", {"reports": [{
                "source": f"source_{i}",
                "threat_type": "anthrax",
                "severity_score": 0.95,
                "corroboration_count": 3,
                "timestamp": 1000 + i,
                "evidence_id": f"osint_{i}",
            }]})
            engine.evaluate()

        assert engine.snapshot.alert_level.value < AlertLevel.CONFIRMED.value

    def test_multi_agent_can_escalate(self):
        engine = make_engine()

        # Sensor data
        engine.ingest("sensor_monitor", {"readings": [{
            "sensor_id": "bio_1",
            "reading_type": "aerosol",
            "normalized_value": 0.7,
            "calibration_confidence": 0.85,
            "timestamp": 1000,
            "evidence_id": "s1",
        }]})

        # Epi data
        engine.ingest("epi_analyst", {"indicators": [{
            "indicator_type": "syndromic",
            "normalized_severity": 0.65,
            "lab_confirmed": False,
            "sample_size": 5,
            "timestamp": 1001,
            "evidence_id": "e1",
        }]})

        engine.evaluate()
        # With two agents providing corroborating data, should escalate
        assert engine.snapshot.alert_level.value >= AlertLevel.ELEVATED.value

    def test_safe_mode_governance(self):
        engine = make_engine()
        engine.enter_safe_mode()
        assert engine.snapshot.safe_mode is True
        assert engine.snapshot.alert_level == AlertLevel.SAFE

        # Feed alarming data
        engine.ingest("sensor_monitor", {"readings": [{
            "sensor_id": "bio_1",
            "reading_type": "aerosol",
            "normalized_value": 0.95,
            "calibration_confidence": 0.9,
            "timestamp": 1000,
            "evidence_id": "s1",
        }]})
        engine.evaluate()

        # Still in safe mode
        assert engine.snapshot.alert_level == AlertLevel.SAFE

    def test_human_override(self):
        engine = make_engine()
        engine.human_override(
            operator_id="dr_smith",
            proposed_level=AlertLevel.CONFIRMED,
            rationale="Lab confirmed anthrax exposure in facility",
        )
        assert engine.snapshot.alert_level == AlertLevel.CONFIRMED

    def test_no_invariant_violations_under_normal_operation(self):
        engine = make_engine()

        # Normal operation cycle
        engine.ingest("sensor_monitor", {"readings": [{
            "sensor_id": "bio_1",
            "reading_type": "aerosol",
            "normalized_value": 0.3,
            "calibration_confidence": 0.8,
            "timestamp": 1000,
            "evidence_id": "s1",
        }]})
        engine.evaluate()
        engine.tick()

        assert len(engine.invariant_violations) == 0

    def test_duplicate_agent_registration_fails(self):
        engine = make_engine()
        with pytest.raises(ValueError):
            engine.register_agent(OSINTAgent())

    def test_unknown_agent_ingest_fails(self):
        engine = make_engine()
        with pytest.raises(ValueError):
            engine.ingest("nonexistent_agent", {})

    def test_uncertainty_tracked(self):
        engine = make_engine()

        # With imperfect data, uncertainty should be non-zero
        engine.ingest("sensor_monitor", {"readings": [{
            "sensor_id": "bio_1",
            "reading_type": "aerosol",
            "normalized_value": 0.5,
            "calibration_confidence": 0.7,
            "timestamp": 1000,
            "evidence_id": "s1",
        }]})

        assert engine.snapshot.uncertainty > 0

    def test_conflicting_signals_produce_high_uncertainty(self):
        engine = make_engine()

        # Sensor says threat
        engine.ingest("sensor_monitor", {"readings": [{
            "sensor_id": "bio_1",
            "reading_type": "aerosol",
            "normalized_value": 0.9,
            "calibration_confidence": 0.85,
            "timestamp": 1000,
            "evidence_id": "s1",
        }]})

        # Epi says no threat
        engine.ingest("epi_analyst", {"indicators": [{
            "indicator_type": "syndromic",
            "normalized_severity": 0.05,
            "lab_confirmed": False,
            "sample_size": 100,
            "timestamp": 1001,
            "evidence_id": "e1",
        }]})

        # Uncertainty should reflect conflicting data
        assert engine.snapshot.uncertainty > 0
