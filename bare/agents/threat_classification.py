"""
Threat Classification Agent

Distinguishes natural outbreak vs accidental release vs potential hostile
event using signal correlation across multiple axes:

    1. Spatial pattern: Natural outbreaks radiate from a focal point;
       simultaneous multi-city events suggest intentional release.
    2. Pathogen profile: Engineered or weaponized agents (e.g. anthrax,
       smallpox) carry higher hostile priors.
    3. Temporal signature: Near-simultaneous onset in dispersed
       locations is atypical for natural emergence.
    4. Anomaly concordance: Agreement between OSINT and sensor
       streams increases confidence in non-natural origin.

Events exceeding the hostile threshold or exceeding WARNING severity
are flagged for mandatory human escalation.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any

from bare.core.base_agent import BaseAgent
from bare.core.message_bus import MessageBus, Topics
from bare.schemas.events import (
    AgentRole,
    EpiAssessment,
    SeverityLevel,
    ThreatAssessment,
    ThreatCategory,
)


# ---------------------------------------------------------------------------
# Threat prior configuration
# ---------------------------------------------------------------------------

# Pathogens with elevated hostile-use priors based on CDC Category A/B
# classification and historical bioweapons programs.
HIGH_HOSTILE_PRIOR: set[str] = {
    "anthrax", "smallpox", "plague", "botulism", "tularemia",
}

# Moderate hostile prior — possible dual-use or historical weaponization
MODERATE_HOSTILE_PRIOR: set[str] = {
    "ebola", "marburg", "novel_respiratory",
}


def _compute_severity(confidence: float, r0: float, is_hostile: bool) -> SeverityLevel:
    """Map quantitative metrics to graduated severity levels.

    Thresholds:
        EMERGENCY: hostile with high confidence, OR R₀ > 3 with high confidence
        WARNING:   R₀ > 2 or confidence > 0.7
        ADVISORY:  R₀ > 1 or confidence > 0.4
        WATCH:     everything else
    """
    if is_hostile and confidence > 0.6:
        return SeverityLevel.EMERGENCY
    if r0 > 3.0 and confidence > 0.7:
        return SeverityLevel.EMERGENCY
    if r0 > 2.0 or confidence > 0.7:
        return SeverityLevel.WARNING
    if r0 > 1.0 or confidence > 0.4:
        return SeverityLevel.ADVISORY
    return SeverityLevel.WATCH


def _classify_threat(
    pathogen: str,
    confidence: float,
    region_count: int,
    source_diversity: int,
) -> tuple[ThreatCategory, float]:
    """Classify the threat category and return (category, category_confidence).

    Heuristic classification:
        - Multiple simultaneous regions + high-hostile pathogen → POTENTIAL_HOSTILE
        - Single region + moderate confidence → NATURAL_OUTBREAK
        - Ambiguous signals → UNDETERMINED
        - Category confidence reflects how well the signal pattern
          matches the assessed category.
    """
    pathogen_lower = pathogen.lower() if pathogen else ""

    hostile_prior = 0.0
    if pathogen_lower in HIGH_HOSTILE_PRIOR:
        hostile_prior = 0.4
    elif pathogen_lower in MODERATE_HOSTILE_PRIOR:
        hostile_prior = 0.2

    # Multi-region simultaneous events increase hostile score
    spatial_factor = min(1.0, region_count / 3.0) * 0.3

    # Source diversity (OSINT + sensors agreeing) increases confidence
    concordance_factor = min(1.0, source_diversity / 2.0) * 0.2

    hostile_score = hostile_prior + spatial_factor + concordance_factor
    hostile_score = min(1.0, hostile_score) * confidence

    if hostile_score > 0.5:
        return ThreatCategory.POTENTIAL_HOSTILE, hostile_score
    if hostile_score > 0.25:
        return ThreatCategory.ACCIDENTAL_RELEASE, hostile_score
    if confidence > 0.3:
        return ThreatCategory.NATURAL_OUTBREAK, confidence
    return ThreatCategory.UNDETERMINED, max(0.1, confidence * 0.5)


# ---------------------------------------------------------------------------
# Agent implementation
# ---------------------------------------------------------------------------

class ThreatClassificationAgent(BaseAgent):
    """Classifies biological events and determines severity."""

    def __init__(
        self,
        bus: MessageBus,
        agent_id: str = "threat_classification_01",
    ) -> None:
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.THREAT_CLASSIFICATION,
            bus=bus,
            cycle_interval=1.0,
        )
        self._input_queue: asyncio.Queue[Any] | None = None
        # Track recent assessments by pathogen for multi-region correlation
        self._recent_by_pathogen: dict[str, list[EpiAssessment]] = defaultdict(list)

    async def start(self) -> None:
        self._input_queue = await self.bus.subscribe(
            Topics.EPI_ASSESSMENTS, self.agent_id
        )
        await super().start()

    async def _run_cycle(self) -> None:
        if self._input_queue is None:
            return

        batch: list[EpiAssessment] = []
        try:
            while True:
                assessment = self._input_queue.get_nowait()
                if isinstance(assessment, EpiAssessment):
                    batch.append(assessment)
        except asyncio.QueueEmpty:
            pass

        for epi in batch:
            pathogen = epi.pathogen
            self._recent_by_pathogen[pathogen].append(epi)

            # Count distinct regions reporting this pathogen
            regions = {a.region for a in self._recent_by_pathogen[pathogen]}
            region_count = len(regions)

            # Count distinct contributing report sources
            all_reports = set()
            for a in self._recent_by_pathogen[pathogen]:
                all_reports.update(a.contributing_reports)
            source_diversity = min(len(all_reports), 5)

            category, cat_confidence = _classify_threat(
                pathogen, epi.confidence, region_count, source_diversity,
            )

            is_hostile = category == ThreatCategory.POTENTIAL_HOSTILE
            severity = _compute_severity(
                epi.confidence, epi.r0_estimate, is_hostile,
            )

            requires_escalation = (
                severity in (SeverityLevel.WARNING, SeverityLevel.EMERGENCY)
                or is_hostile
            )

            factors = []
            if pathogen.lower() in HIGH_HOSTILE_PRIOR:
                factors.append(f"pathogen '{pathogen}' is CDC Category A/B")
            if region_count > 1:
                factors.append(f"detected in {region_count} regions simultaneously")
            if epi.r0_estimate > 2.0:
                factors.append(f"R₀ estimate {epi.r0_estimate:.2f} indicates high transmissibility")

            threat = ThreatAssessment(
                region=epi.region,
                pathogen=pathogen,
                category=category,
                category_confidence=cat_confidence,
                severity=severity,
                requires_human_escalation=requires_escalation,
                correlation_factors=tuple(factors),
                narrative=(
                    f"Threat assessment for '{pathogen}' in '{epi.region}': "
                    f"classified as {category.value} (confidence={cat_confidence:.3f}). "
                    f"Severity: {severity.value}. "
                    f"{'HUMAN ESCALATION REQUIRED. ' if requires_escalation else ''}"
                    f"Based on {len(self._recent_by_pathogen[pathogen])} epidemiological "
                    f"assessments across {region_count} region(s)."
                ),
            )
            await self.bus.publish(Topics.THREAT_ASSESSMENTS, threat)
            self.logger.info(
                "Threat: %s in %s → %s (%s) escalation=%s",
                pathogen, epi.region, category.value, severity.value,
                requires_escalation,
            )

        # Prune old assessments (keep last 50 per pathogen)
        for pathogen in self._recent_by_pathogen:
            if len(self._recent_by_pathogen[pathogen]) > 50:
                self._recent_by_pathogen[pathogen] = (
                    self._recent_by_pathogen[pathogen][-50:]
                )
