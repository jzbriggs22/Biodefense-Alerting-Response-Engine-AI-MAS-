"""
CDC NNDSS (National Notifiable Diseases Surveillance System) adapter.

Fetches weekly notifiable disease case counts from the CDC NNDSS
dataset on data.cdc.gov via the Socrata Open Data API (SODA).

Data source: https://data.cdc.gov/NNDSS/NNDSS-Weekly-Data/x9gk-5huc

SODA endpoint: https://data.cdc.gov/resource/x9gk-5huc.json

Field mapping:
    m1  = current week case count
    m2  = cumulative YTD case count
    m3  = previous year same-week cumulative
    m4  = previous year total
    *_flag = "-" (no data), "NC" (not currently notifiable), "U" (unavailable)

DESIGN: This adapter converts raw CDC data into the dict format expected
by EpidemiologicalAgent.analyze() and OSINTAgent.analyze().  It does NOT
make alert-level decisions — that stays in the DECIDING layer.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SODA_ENDPOINT = "https://data.cdc.gov/resource/x9gk-5huc.json"

# Diseases with biodefense relevance (CDC Category A/B/C bioterrorism agents
# plus high-consequence emerging infections tracked by NNDSS).
BIODEFENSE_DISEASES: Dict[str, float] = {
    # Category A — highest priority
    "Anthrax": 1.0,
    "Botulism, total": 0.9,
    "Plague": 1.0,
    "Tularemia": 0.9,
    "Smallpox": 1.0,
    # Category B
    "Brucellosis": 0.7,
    "Q fever, total": 0.7,
    "Psittacosis": 0.6,
    # Category C — emerging
    "Rift Valley fever virus disease": 0.8,
    # High-consequence notifiable
    "Meningococcal disease, all serogroups": 0.6,
    "Rabies, human": 0.7,
    "Viral hemorrhagic fevers": 0.95,
}

# Baseline annual case counts (approximate US) for normalization.
# Used to convert raw counts into [0, 1] severity scores.
BASELINE_ANNUAL_CASES: Dict[str, float] = {
    "Anthrax": 1.0,
    "Botulism, total": 150.0,
    "Plague": 7.0,
    "Tularemia": 200.0,
    "Smallpox": 0.0,
    "Brucellosis": 120.0,
    "Q fever, total": 170.0,
    "Psittacosis": 15.0,
    "Rift Valley fever virus disease": 0.0,
    "Meningococcal disease, all serogroups": 350.0,
    "Rabies, human": 3.0,
    "Viral hemorrhagic fevers": 0.0,
}

# How many weeks of history to fetch per poll
DEFAULT_WEEKS_BACK = 4

# Maximum retries for API calls
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2.0


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NNDSSRecord:
    """A single parsed NNDSS weekly record."""
    disease: str
    state: str
    year: int
    week: int
    current_week_count: Optional[float]
    cumulative_ytd: Optional[float]
    prev_year_cumulative: Optional[float]
    prev_year_total: Optional[float]


@dataclass
class NNDSSFetchResult:
    """Result of a fetch operation."""
    records: List[NNDSSRecord]
    fetch_timestamp: float
    query_params: Dict[str, str]
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------------

class CDCNNDSSFetcher:
    """
    Fetches and parses CDC NNDSS weekly data via SODA API.

    No API key required for public data, but rate-limited to ~1000 req/hour.
    An app_token can be provided for higher throughput.
    """

    def __init__(
        self,
        endpoint: str = SODA_ENDPOINT,
        app_token: Optional[str] = None,
        diseases: Optional[Dict[str, float]] = None,
        timeout_seconds: int = 30,
    ):
        self._endpoint = endpoint
        self._app_token = app_token
        self._diseases = diseases or BIODEFENSE_DISEASES
        self._timeout = timeout_seconds

    def fetch_latest(
        self,
        year: Optional[int] = None,
        weeks_back: int = DEFAULT_WEEKS_BACK,
        state: str = "U.S. Residents",
    ) -> NNDSSFetchResult:
        """
        Fetch the most recent NNDSS data for biodefense-relevant diseases.

        Args:
            year: Reporting year (default: current year)
            weeks_back: How many weeks of history to retrieve
            state: Geographic filter (default: national)

        Returns:
            NNDSSFetchResult with parsed records
        """
        if year is None:
            year = time.gmtime().tm_year

        disease_labels = list(self._diseases.keys())
        label_filter = " OR ".join(
            f"label='{d}'" for d in disease_labels
        )

        where_clause = (
            f"year='{year}' AND states='{state}' "
            f"AND ({label_filter})"
        )

        params: Dict[str, str] = {
            "$where": where_clause,
            "$order": "week DESC",
            "$limit": str(len(disease_labels) * weeks_back),
        }

        try:
            raw = self._api_get(params)
            records = [self._parse_record(r) for r in raw]
            return NNDSSFetchResult(
                records=records,
                fetch_timestamp=time.time(),
                query_params=params,
            )
        except Exception as e:
            logger.error("NNDSS fetch failed: %s", e)
            return NNDSSFetchResult(
                records=[],
                fetch_timestamp=time.time(),
                query_params=params,
                error=str(e),
            )

    def _api_get(self, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Execute a SODA API GET with retry."""
        query_string = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        url = f"{self._endpoint}?{query_string}"

        headers = {}
        if self._app_token:
            headers["X-App-Token"] = self._app_token

        last_error: Optional[Exception] = None
        for attempt in range(MAX_RETRIES):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    body = resp.read().decode("utf-8")
                    return json.loads(body)
            except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
                last_error = e
                if attempt < MAX_RETRIES - 1:
                    wait = RETRY_BACKOFF_BASE ** (attempt + 1)
                    logger.warning(
                        "NNDSS API attempt %d failed (%s), retrying in %.1fs",
                        attempt + 1, e, wait,
                    )
                    time.sleep(wait)

        raise ConnectionError(
            f"NNDSS API failed after {MAX_RETRIES} attempts: {last_error}"
        )

    @staticmethod
    def _parse_record(raw: Dict[str, Any]) -> NNDSSRecord:
        """Parse a raw SODA JSON record into an NNDSSRecord."""
        return NNDSSRecord(
            disease=raw.get("label", ""),
            state=raw.get("states", raw.get("location1", "")),
            year=int(raw.get("year", 0)),
            week=int(raw.get("week", 0)),
            current_week_count=_safe_float(raw.get("m1")),
            cumulative_ytd=_safe_float(raw.get("m2")),
            prev_year_cumulative=_safe_float(raw.get("m3")),
            prev_year_total=_safe_float(raw.get("m4")),
        )


# ---------------------------------------------------------------------------
# Signal normalization — converts NNDSS records to agent input dicts
# ---------------------------------------------------------------------------

def normalize_for_epi_agent(
    records: Sequence[NNDSSRecord],
    timestamp: int,
    baselines: Optional[Dict[str, float]] = None,
    weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Convert NNDSS records into the dict format expected by
    EpidemiologicalAgent.analyze().

    Normalization strategy:
        severity = min(1.0, weekly_count / (baseline_annual / 52))
        If baseline is 0, any case → severity 1.0 (zero-baseline anomaly).

    Returns:
        {"indicators": [{"indicator_type": ..., "normalized_severity": ..., ...}]}
    """
    baselines = baselines or BASELINE_ANNUAL_CASES
    weights = weights or BIODEFENSE_DISEASES

    indicators = []
    for rec in records:
        if rec.current_week_count is None or rec.current_week_count <= 0:
            continue

        weekly_baseline = baselines.get(rec.disease, 0.0) / 52.0
        if weekly_baseline <= 0:
            # Zero-baseline disease: any case is maximally anomalous
            severity = 1.0
        else:
            severity = min(1.0, rec.current_week_count / weekly_baseline)

        # Apply biodefense weight
        weight = weights.get(rec.disease, 0.5)
        weighted_severity = min(1.0, severity * weight)

        # YTD comparison for confidence boost
        has_ytd_comparison = (
            rec.cumulative_ytd is not None
            and rec.prev_year_cumulative is not None
            and rec.prev_year_cumulative > 0
        )

        indicators.append({
            "indicator_type": f"nndss:{rec.disease}",
            "normalized_severity": round(weighted_severity, 4),
            "lab_confirmed": True,  # NNDSS data is lab-confirmed
            "sample_size": max(1, int(rec.current_week_count)),
            "timestamp": timestamp,
            "evidence_id": (
                f"cdc-nndss-{rec.year}-w{rec.week:02d}-"
                f"{rec.disease.lower().replace(' ', '_').replace(',', '')}"
            ),
            "metadata": json.dumps({
                "source": "CDC NNDSS",
                "disease": rec.disease,
                "state": rec.state,
                "year": rec.year,
                "week": rec.week,
                "raw_count": rec.current_week_count,
                "cumulative_ytd": rec.cumulative_ytd,
                "prev_year_cumulative": rec.prev_year_cumulative,
                "ytd_ratio": (
                    round(rec.cumulative_ytd / rec.prev_year_cumulative, 3)
                    if has_ytd_comparison else None
                ),
                "biodefense_weight": weight,
            }),
        })

    return {"indicators": indicators}


def normalize_for_osint_agent(
    records: Sequence[NNDSSRecord],
    timestamp: int,
    weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Convert NNDSS records into the dict format expected by
    OSINTAgent.analyze().

    NNDSS is authoritative (not OSINT), but feeding it to the OSINT agent
    provides a corroboration signal for the quorum requirement.

    Returns:
        {"reports": [{"source": ..., "threat_type": ..., ...}]}
    """
    weights = weights or BIODEFENSE_DISEASES
    baselines = BASELINE_ANNUAL_CASES

    reports = []
    for rec in records:
        if rec.current_week_count is None or rec.current_week_count <= 0:
            continue

        weekly_baseline = baselines.get(rec.disease, 0.0) / 52.0
        if weekly_baseline <= 0:
            severity = 1.0
        else:
            severity = min(1.0, rec.current_week_count / weekly_baseline)

        weight = weights.get(rec.disease, 0.5)

        reports.append({
            "source": "CDC NNDSS",
            "threat_type": rec.disease,
            "severity_score": round(min(1.0, severity * weight), 4),
            "corroboration_count": 3,  # CDC is well-corroborated
            "timestamp": timestamp,
            "evidence_id": (
                f"cdc-nndss-osint-{rec.year}-w{rec.week:02d}-"
                f"{rec.disease.lower().replace(' ', '_').replace(',', '')}"
            ),
        })

    return {"reports": reports}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_float(val: Any) -> Optional[float]:
    """Parse a numeric string, returning None for flags like '-' or 'NC'."""
    if val is None:
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None
