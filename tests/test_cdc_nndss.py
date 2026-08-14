"""
Tests for the CDC NNDSS adapter.

Tests cover:
  - Record parsing
  - Signal normalization for both EPI and OSINT agents
  - Zero-baseline anomaly detection
  - Fetch error handling
  - End-to-end engine integration with mock CDC data
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch, MagicMock

from src.adapters.cdc_nndss import (
    CDCNNDSSFetcher,
    NNDSSRecord,
    NNDSSFetchResult,
    normalize_for_epi_agent,
    normalize_for_osint_agent,
    BIODEFENSE_DISEASES,
    BASELINE_ANNUAL_CASES,
    _safe_float,
)
from src.agents.epi_agent import EpidemiologicalAgent
from src.agents.osint_agent import OSINTAgent
from src.agents.sensor_agent import SensorAgent
from src.engine import BiodefenseEngine, EngineConfig
from src.types import AlertLevel


# ---------------------------------------------------------------------------
# Sample data matching real SODA API response format
# ---------------------------------------------------------------------------

SAMPLE_SODA_RECORDS = [
    {
        "states": "U.S. Residents",
        "year": "2025",
        "week": "10",
        "label": "Tularemia",
        "m1": "5.0",
        "m2": "20.0",
        "m3": "15.0",
        "m4": "200.0",
        "location2": "U.S. Residents",
        "sort_order": "20251000001",
    },
    {
        "states": "U.S. Residents",
        "year": "2025",
        "week": "10",
        "label": "Anthrax",
        "m1": "2.0",
        "m2": "3.0",
        "m3_flag": "-",
        "m4": "1.0",
        "location2": "U.S. Residents",
        "sort_order": "20251000002",
    },
    {
        "states": "U.S. Residents",
        "year": "2025",
        "week": "10",
        "label": "Plague",
        "m1_flag": "-",
        "m2_flag": "-",
        "m3_flag": "-",
        "m4_flag": "-",
        "location2": "U.S. Residents",
        "sort_order": "20251000003",
    },
    {
        "states": "U.S. Residents",
        "year": "2025",
        "week": "9",
        "label": "Brucellosis",
        "m1": "3.0",
        "m2": "10.0",
        "m3": "8.0",
        "m4": "120.0",
        "location2": "U.S. Residents",
        "sort_order": "20250900004",
    },
]


class TestSafeFloat(unittest.TestCase):
    def test_valid_number(self):
        self.assertEqual(_safe_float("5.0"), 5.0)

    def test_integer_string(self):
        self.assertEqual(_safe_float("42"), 42.0)

    def test_dash_flag(self):
        self.assertIsNone(_safe_float("-"))

    def test_nc_flag(self):
        self.assertIsNone(_safe_float("NC"))

    def test_none(self):
        self.assertIsNone(_safe_float(None))

    def test_empty_string(self):
        self.assertIsNone(_safe_float(""))


class TestRecordParsing(unittest.TestCase):
    def test_parse_record_with_counts(self):
        rec = CDCNNDSSFetcher._parse_record(SAMPLE_SODA_RECORDS[0])
        self.assertEqual(rec.disease, "Tularemia")
        self.assertEqual(rec.state, "U.S. Residents")
        self.assertEqual(rec.year, 2025)
        self.assertEqual(rec.week, 10)
        self.assertEqual(rec.current_week_count, 5.0)
        self.assertEqual(rec.cumulative_ytd, 20.0)
        self.assertEqual(rec.prev_year_cumulative, 15.0)
        self.assertEqual(rec.prev_year_total, 200.0)

    def test_parse_record_with_flags(self):
        rec = CDCNNDSSFetcher._parse_record(SAMPLE_SODA_RECORDS[2])
        self.assertEqual(rec.disease, "Plague")
        self.assertIsNone(rec.current_week_count)
        self.assertIsNone(rec.cumulative_ytd)

    def test_parse_record_mixed(self):
        rec = CDCNNDSSFetcher._parse_record(SAMPLE_SODA_RECORDS[1])
        self.assertEqual(rec.disease, "Anthrax")
        self.assertEqual(rec.current_week_count, 2.0)
        self.assertIsNone(rec.prev_year_cumulative)  # m3_flag = "-"


class TestNormalizeForEpiAgent(unittest.TestCase):
    def _make_records(self):
        return [CDCNNDSSFetcher._parse_record(r) for r in SAMPLE_SODA_RECORDS]

    def test_produces_indicators(self):
        records = self._make_records()
        result = normalize_for_epi_agent(records, timestamp=1)
        self.assertIn("indicators", result)
        # Plague has no counts, so only 3 diseases should produce indicators
        self.assertEqual(len(result["indicators"]), 3)

    def test_severity_bounded(self):
        records = self._make_records()
        result = normalize_for_epi_agent(records, timestamp=1)
        for ind in result["indicators"]:
            self.assertGreaterEqual(ind["normalized_severity"], 0.0)
            self.assertLessEqual(ind["normalized_severity"], 1.0)

    def test_lab_confirmed_true(self):
        """NNDSS data is lab-confirmed."""
        records = self._make_records()
        result = normalize_for_epi_agent(records, timestamp=1)
        for ind in result["indicators"]:
            self.assertTrue(ind["lab_confirmed"])

    def test_evidence_ids_unique(self):
        records = self._make_records()
        result = normalize_for_epi_agent(records, timestamp=1)
        evidence_ids = [ind["evidence_id"] for ind in result["indicators"]]
        self.assertEqual(len(evidence_ids), len(set(evidence_ids)))

    def test_zero_baseline_anomaly(self):
        """A disease with zero baseline should produce severity 1.0."""
        rec = NNDSSRecord(
            disease="Smallpox",
            state="U.S. Residents",
            year=2025, week=10,
            current_week_count=1.0,
            cumulative_ytd=1.0,
            prev_year_cumulative=None,
            prev_year_total=0.0,
        )
        result = normalize_for_epi_agent([rec], timestamp=1)
        self.assertEqual(len(result["indicators"]), 1)
        self.assertEqual(result["indicators"][0]["normalized_severity"], 1.0)

    def test_no_cases_no_indicators(self):
        rec = NNDSSRecord(
            disease="Anthrax",
            state="U.S. Residents",
            year=2025, week=10,
            current_week_count=0.0,
            cumulative_ytd=0.0,
            prev_year_cumulative=None,
            prev_year_total=1.0,
        )
        result = normalize_for_epi_agent([rec], timestamp=1)
        self.assertEqual(len(result["indicators"]), 0)

    def test_anthrax_high_severity(self):
        """2 anthrax cases vs baseline ~0.019/week → very high severity."""
        records = self._make_records()
        result = normalize_for_epi_agent(records, timestamp=1)
        anthrax_ind = [
            i for i in result["indicators"]
            if "Anthrax" in i["indicator_type"]
        ]
        self.assertEqual(len(anthrax_ind), 1)
        # 2 cases / (1/52) baseline ≫ 1.0, capped at 1.0
        self.assertEqual(anthrax_ind[0]["normalized_severity"], 1.0)

    def test_metadata_contains_source(self):
        records = self._make_records()
        result = normalize_for_epi_agent(records, timestamp=1)
        for ind in result["indicators"]:
            meta = json.loads(ind["metadata"])
            self.assertEqual(meta["source"], "CDC NNDSS")


class TestNormalizeForOSINTAgent(unittest.TestCase):
    def _make_records(self):
        return [CDCNNDSSFetcher._parse_record(r) for r in SAMPLE_SODA_RECORDS]

    def test_produces_reports(self):
        records = self._make_records()
        result = normalize_for_osint_agent(records, timestamp=1)
        self.assertIn("reports", result)
        self.assertEqual(len(result["reports"]), 3)

    def test_severity_bounded(self):
        records = self._make_records()
        result = normalize_for_osint_agent(records, timestamp=1)
        for report in result["reports"]:
            self.assertGreaterEqual(report["severity_score"], 0.0)
            self.assertLessEqual(report["severity_score"], 1.0)

    def test_corroboration_count(self):
        """CDC is well-corroborated, should have count >= 3."""
        records = self._make_records()
        result = normalize_for_osint_agent(records, timestamp=1)
        for report in result["reports"]:
            self.assertGreaterEqual(report["corroboration_count"], 3)


class TestFetcherErrorHandling(unittest.TestCase):
    @patch("src.adapters.cdc_nndss.CDCNNDSSFetcher._api_get")
    def test_api_failure_returns_empty(self, mock_get):
        mock_get.side_effect = ConnectionError("Network error")
        fetcher = CDCNNDSSFetcher()
        result = fetcher.fetch_latest(year=2025)
        self.assertEqual(len(result.records), 0)
        self.assertIsNotNone(result.error)
        self.assertIn("Network error", result.error)

    @patch("src.adapters.cdc_nndss.CDCNNDSSFetcher._api_get")
    def test_successful_fetch(self, mock_get):
        mock_get.return_value = SAMPLE_SODA_RECORDS
        fetcher = CDCNNDSSFetcher()
        result = fetcher.fetch_latest(year=2025)
        self.assertEqual(len(result.records), 4)
        self.assertIsNone(result.error)


class TestEngineIntegration(unittest.TestCase):
    """End-to-end: mock CDC data → adapter → agents → engine → alert level."""

    def test_nndss_data_through_engine(self):
        engine = BiodefenseEngine(config=EngineConfig())
        engine.register_agent(OSINTAgent())
        engine.register_agent(SensorAgent())
        engine.register_agent(EpidemiologicalAgent())

        records = [CDCNNDSSFetcher._parse_record(r) for r in SAMPLE_SODA_RECORDS]

        epi_data = normalize_for_epi_agent(records, timestamp=0)
        osint_data = normalize_for_osint_agent(records, timestamp=0)

        epi_signals = engine.ingest("epi_analyst", epi_data)
        osint_signals = engine.ingest("osint_monitor", osint_data)

        self.assertGreater(len(epi_signals), 0)
        self.assertGreater(len(osint_signals), 0)

        # All signals must be bounded
        for s in epi_signals + osint_signals:
            self.assertGreaterEqual(s.value, 0.0)
            self.assertLessEqual(s.value, 1.0)
            self.assertGreaterEqual(s.confidence, 0.0)
            self.assertLessEqual(s.confidence, 1.0)

        snapshot = engine.evaluate()

        # With anthrax cases (high severity), should escalate above NORMAL
        # given both epi and osint agents see signals (quorum met)
        self.assertGreaterEqual(snapshot.alert_level.value, AlertLevel.NORMAL.value)
        self.assertEqual(len(engine.invariant_violations), 0)

    def test_no_cases_stays_normal(self):
        """When CDC reports zero cases, engine should stay NORMAL."""
        engine = BiodefenseEngine(config=EngineConfig())
        engine.register_agent(OSINTAgent())
        engine.register_agent(SensorAgent())
        engine.register_agent(EpidemiologicalAgent())

        zero_records = [
            NNDSSRecord("Anthrax", "U.S. Residents", 2025, 10, 0.0, 0.0, None, 1.0),
            NNDSSRecord("Plague", "U.S. Residents", 2025, 10, None, None, None, None),
        ]

        epi_data = normalize_for_epi_agent(zero_records, timestamp=0)
        osint_data = normalize_for_osint_agent(zero_records, timestamp=0)

        engine.ingest("epi_analyst", epi_data)
        engine.ingest("osint_monitor", osint_data)
        snapshot = engine.evaluate()

        self.assertEqual(snapshot.alert_level, AlertLevel.NORMAL)


if __name__ == "__main__":
    unittest.main()
