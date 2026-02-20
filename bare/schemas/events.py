"""
Core event and data schemas for the BARE system.

All inter-agent communication uses these typed dataclasses.
Every schema is immutable (frozen) to prevent accidental mutation
during pipeline processing, and every instance carries a unique
event_id and UTC timestamp for full traceability.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SignalSource(Enum):
    """Origin category for an ingested signal."""
    NEWS = "news"
    PREPRINT = "preprint"
    WHO_BULLETIN = "who_bulletin"
    CDC_BULLETIN = "cdc_bulletin"
    SOCIAL_TREND = "social_trend"
    WASTEWATER = "wastewater"
    SYNDROMIC = "syndromic"
    EMS_METADATA = "ems_metadata"
    WEARABLE_AGGREGATE = "wearable_aggregate"
    SIMULATED = "simulated"


class SeverityLevel(Enum):
    """Graduated severity for alerts."""
    WATCH = "watch"           # Elevated monitoring; no action required
    ADVISORY = "advisory"     # Possible event; notify analysts
    WARNING = "warning"       # Probable event; notify public health officials
    EMERGENCY = "emergency"   # Confirmed high-severity; full escalation


class ThreatCategory(Enum):
    """Assessed origin of a biological event."""
    NATURAL_OUTBREAK = "natural_outbreak"
    ACCIDENTAL_RELEASE = "accidental_release"
    POTENTIAL_HOSTILE = "potential_hostile"
    UNDETERMINED = "undetermined"


class AgentRole(Enum):
    """Identifies agents in the system."""
    OSINT_INGESTION = "osint_ingestion"
    IOT_SENSOR = "iot_sensor"
    EPI_REASONING = "epi_reasoning"
    THREAT_CLASSIFICATION = "threat_classification"
    RESPONSE_ORCHESTRATION = "response_orchestration"
    SUPERVISOR = "supervisor"


# ---------------------------------------------------------------------------
# Signal schemas — the raw inputs from ingestion agents
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RawSignal:
    """A single observation from any data source.

    Carries no PII. The `source_ref` is an opaque identifier
    (e.g. article hash, sensor serial) that allows provenance
    tracing without storing personal data.
    """
    signal_id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_utcnow)
    source: SignalSource = SignalSource.SIMULATED
    source_ref: str = ""
    region: str = ""               # ISO 3166-1 alpha-2 or free-text region
    latitude: float | None = None
    longitude: float | None = None
    pathogen_hint: str = ""        # e.g. "influenza", "anthrax", ""
    keyword_hits: tuple[str, ...] = ()
    raw_score: float = 0.0        # Source-specific relevance score [0, 1]
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Anomaly assessment — output of statistical / NLP analysis
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AnomalyReport:
    """Produced by ingestion agents when a signal crosses anomaly thresholds."""
    report_id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_utcnow)
    originating_agent: AgentRole = AgentRole.OSINT_INGESTION
    region: str = ""
    pathogen_hint: str = ""
    anomaly_score: float = 0.0    # [0, 1] — higher is more anomalous
    baseline_value: float = 0.0
    observed_value: float = 0.0
    z_score: float = 0.0
    contributing_signals: tuple[str, ...] = ()  # signal_ids
    explanation: str = ""


# ---------------------------------------------------------------------------
# Epidemiological assessment
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EpiAssessment:
    """Output of the Epidemiological Reasoning Agent."""
    assessment_id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_utcnow)
    region: str = ""
    pathogen: str = ""
    r0_estimate: float = 0.0
    doubling_time_days: float | None = None
    confidence: float = 0.0          # [0, 1]
    false_positive_prob: float = 1.0  # [0, 1]
    seir_parameters: dict[str, float] = field(default_factory=dict)
    contributing_reports: tuple[str, ...] = ()
    narrative: str = ""


# ---------------------------------------------------------------------------
# Threat classification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThreatAssessment:
    """Output of the Threat Classification Agent."""
    assessment_id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_utcnow)
    region: str = ""
    pathogen: str = ""
    category: ThreatCategory = ThreatCategory.UNDETERMINED
    category_confidence: float = 0.0   # [0, 1]
    severity: SeverityLevel = SeverityLevel.WATCH
    requires_human_escalation: bool = False
    correlation_factors: tuple[str, ...] = ()
    narrative: str = ""


# ---------------------------------------------------------------------------
# Alert — the final output to downstream consumers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Alert:
    """A structured alert ready for delivery to stakeholders."""
    alert_id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_utcnow)
    severity: SeverityLevel = SeverityLevel.WATCH
    region: str = ""
    pathogen: str = ""
    threat_category: ThreatCategory = ThreatCategory.UNDETERMINED
    headline: str = ""
    detail: str = ""
    recommended_actions: tuple[str, ...] = ()
    recipients: tuple[str, ...] = ()         # role-based, not PII
    playbook_id: str = ""
    contributing_assessment_ids: tuple[str, ...] = ()
    confidence: float = 0.0
    false_positive_prob: float = 1.0
    requires_human_confirmation: bool = True
    audit_chain: tuple[str, ...] = ()        # ordered list of event_ids


# ---------------------------------------------------------------------------
# Audit log entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuditEntry:
    """Immutable record for the audit log."""
    entry_id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_utcnow)
    agent: AgentRole = AgentRole.SUPERVISOR
    action: str = ""
    input_ids: tuple[str, ...] = ()
    output_ids: tuple[str, ...] = ()
    decision: str = ""
    rationale: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
