"""
Response Orchestration Agent

Generates structured alerts for EMS, hospitals, and public health
authorities. Triggers predefined response playbooks based on severity
and threat classification.

Responsibilities:
    1. Translate ThreatAssessments into actionable Alerts.
    2. Select the appropriate response playbook.
    3. Determine recipient tiers based on severity.
    4. Enforce rate-limiting to prevent alert fatigue.
    5. Ensure alerts requiring human confirmation are held until
       acknowledged (simulated here as a flag).

Alert outputs are WRITE-ONLY — this agent does not ingest external
data, only internal threat assessments.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from bare.core.base_agent import BaseAgent
from bare.core.message_bus import MessageBus, Topics
from bare.schemas.events import (
    AgentRole,
    Alert,
    SeverityLevel,
    ThreatAssessment,
    ThreatCategory,
)


# ---------------------------------------------------------------------------
# Playbook definitions
# ---------------------------------------------------------------------------

PLAYBOOKS: dict[str, dict[str, Any]] = {
    "PB-001-NATURAL-WATCH": {
        "id": "PB-001",
        "name": "Natural Outbreak — Watch",
        "actions": (
            "Increase monitoring frequency for affected region",
            "Notify regional epidemiologist on-call",
            "Pre-stage situational awareness report",
        ),
        "recipients": ("regional_epi_team",),
        "escalation_hours": 24,
    },
    "PB-002-NATURAL-ADVISORY": {
        "id": "PB-002",
        "name": "Natural Outbreak — Advisory",
        "actions": (
            "Issue advisory to hospital networks in affected region",
            "Activate enhanced syndromic surveillance",
            "Brief state health officer",
            "Prepare laboratory confirmation requests",
        ),
        "recipients": ("regional_epi_team", "hospital_networks", "state_health_officer"),
        "escalation_hours": 12,
    },
    "PB-003-NATURAL-WARNING": {
        "id": "PB-003",
        "name": "Natural Outbreak — Warning",
        "actions": (
            "Issue public health warning to all facilities in region",
            "Activate emergency operations center (EOC)",
            "Deploy field investigation teams",
            "Coordinate with CDC Emergency Operations",
            "Initiate medical countermeasure distribution planning",
        ),
        "recipients": (
            "regional_epi_team", "hospital_networks", "state_health_officer",
            "ems_dispatch", "cdc_eoc",
        ),
        "escalation_hours": 4,
    },
    "PB-004-HOSTILE-EMERGENCY": {
        "id": "PB-004",
        "name": "Potential Hostile — Emergency",
        "actions": (
            "IMMEDIATE: Notify FBI WMD Directorate and DHS",
            "Activate National Biosurveillance Integration Center (NBIC)",
            "Issue highest-priority alert to all regional hospitals",
            "Coordinate law enforcement perimeter and evidence preservation",
            "Initiate Strategic National Stockpile (SNS) deployment review",
            "Activate public communication protocols",
        ),
        "recipients": (
            "fbi_wmd", "dhs_ops", "cdc_eoc", "hospital_networks",
            "ems_dispatch", "state_health_officer", "nbic",
        ),
        "escalation_hours": 1,
    },
    "PB-005-GENERAL-EMERGENCY": {
        "id": "PB-005",
        "name": "General — Emergency",
        "actions": (
            "Activate all-hazards emergency protocol",
            "Full hospital network alert",
            "Deploy mobile medical assets",
            "Coordinate with state and federal authorities",
            "Initiate public notification via Emergency Alert System",
        ),
        "recipients": (
            "cdc_eoc", "hospital_networks", "ems_dispatch",
            "state_health_officer", "fema_ops",
        ),
        "escalation_hours": 2,
    },
}


def _select_playbook(
    category: ThreatCategory, severity: SeverityLevel
) -> dict[str, Any]:
    """Select the most appropriate playbook given category and severity."""
    if category == ThreatCategory.POTENTIAL_HOSTILE:
        return PLAYBOOKS["PB-004-HOSTILE-EMERGENCY"]
    if severity == SeverityLevel.EMERGENCY:
        return PLAYBOOKS["PB-005-GENERAL-EMERGENCY"]
    if severity == SeverityLevel.WARNING:
        return PLAYBOOKS["PB-003-NATURAL-WARNING"]
    if severity == SeverityLevel.ADVISORY:
        return PLAYBOOKS["PB-002-NATURAL-ADVISORY"]
    return PLAYBOOKS["PB-001-NATURAL-WATCH"]


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class AlertRateLimiter:
    """Prevents alert fatigue by enforcing minimum intervals per key.

    Keys are (region, pathogen, severity) tuples. An alert is suppressed
    if another alert with the same key was issued within the cooldown
    period.
    """

    def __init__(self, cooldown_seconds: float = 300.0) -> None:
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self._last_issued: dict[tuple[str, str, str], datetime] = {}

    def should_suppress(self, region: str, pathogen: str, severity: str) -> bool:
        key = (region, pathogen, severity)
        now = datetime.now(timezone.utc)
        last = self._last_issued.get(key)
        if last and (now - last) < self.cooldown:
            return True
        return False

    def record(self, region: str, pathogen: str, severity: str) -> None:
        key = (region, pathogen, severity)
        self._last_issued[key] = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Agent implementation
# ---------------------------------------------------------------------------

class ResponseOrchestrationAgent(BaseAgent):
    """Translates threat assessments into alerts and triggers playbooks."""

    def __init__(
        self,
        bus: MessageBus,
        rate_limit_seconds: float = 300.0,
        agent_id: str = "response_orchestration_01",
    ) -> None:
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.RESPONSE_ORCHESTRATION,
            bus=bus,
            cycle_interval=1.0,
        )
        self._input_queue: asyncio.Queue[Any] | None = None
        self._rate_limiter = AlertRateLimiter(cooldown_seconds=rate_limit_seconds)
        self.alerts_generated: int = 0
        self.alerts_suppressed: int = 0

    async def start(self) -> None:
        self._input_queue = await self.bus.subscribe(
            Topics.THREAT_ASSESSMENTS, self.agent_id
        )
        await super().start()

    async def _run_cycle(self) -> None:
        if self._input_queue is None:
            return

        batch: list[ThreatAssessment] = []
        try:
            while True:
                threat = self._input_queue.get_nowait()
                if isinstance(threat, ThreatAssessment):
                    batch.append(threat)
        except asyncio.QueueEmpty:
            pass

        for threat in batch:
            # Rate-limit check
            if self._rate_limiter.should_suppress(
                threat.region, threat.pathogen, threat.severity.value
            ):
                self.alerts_suppressed += 1
                self.logger.debug(
                    "Alert suppressed (rate-limited): %s/%s/%s",
                    threat.region, threat.pathogen, threat.severity.value,
                )
                continue

            playbook = _select_playbook(threat.category, threat.severity)

            alert = Alert(
                severity=threat.severity,
                region=threat.region,
                pathogen=threat.pathogen,
                threat_category=threat.category,
                headline=(
                    f"{threat.severity.value.upper()}: {threat.pathogen} — "
                    f"{threat.category.value.replace('_', ' ').title()} "
                    f"in {threat.region}"
                ),
                detail=threat.narrative,
                recommended_actions=playbook["actions"],
                recipients=playbook["recipients"],
                playbook_id=playbook["id"],
                contributing_assessment_ids=(threat.assessment_id,),
                confidence=threat.category_confidence,
                false_positive_prob=1.0 - threat.category_confidence,
                requires_human_confirmation=threat.requires_human_escalation,
                audit_chain=(threat.assessment_id,),
            )

            await self.bus.publish(Topics.ALERTS, alert)
            self._rate_limiter.record(
                threat.region, threat.pathogen, threat.severity.value
            )
            self.alerts_generated += 1

            self.logger.info(
                "ALERT GENERATED: [%s] %s — playbook %s — recipients: %s",
                alert.severity.value.upper(),
                alert.headline,
                alert.playbook_id,
                ", ".join(alert.recipients),
            )
