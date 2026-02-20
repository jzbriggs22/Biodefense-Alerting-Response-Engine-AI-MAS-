"""
OSINT Ingestion Agent

Monitors global news, academic preprints, social media trend metadata,
and WHO/CDC bulletins for anomalous disease mentions, symptom clusters,
and geographic spikes.

NLP-based anomaly detection approach:
    1. Each incoming text signal is scored against a curated keyword
       taxonomy of pathogen names, symptom descriptors, and outbreak
       indicators.
    2. A sliding-window frequency tracker maintains per-region,
       per-pathogen mention counts.
    3. When the current window's count exceeds the historical baseline
       by a configurable z-score threshold, an AnomalyReport is
       emitted.

This agent performs READ-ONLY ingestion — it never modifies or
acknowledges external sources.
"""

from __future__ import annotations

import asyncio
import math
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from bare.core.base_agent import BaseAgent
from bare.core.message_bus import MessageBus, Topics
from bare.schemas.events import (
    AgentRole,
    AnomalyReport,
    RawSignal,
    SignalSource,
)

# ---------------------------------------------------------------------------
# Keyword taxonomy
# ---------------------------------------------------------------------------

# These are representative; a production system would load from a maintained
# ontology (e.g. SNOMED-CT, ICD-11 mappings).
PATHOGEN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "anthrax": ("anthrax", "bacillus anthracis", "b. anthracis"),
    "smallpox": ("smallpox", "variola", "variola major"),
    "plague": ("plague", "yersinia pestis", "y. pestis", "bubonic"),
    "botulism": ("botulism", "clostridium botulinum", "botulinum toxin"),
    "tularemia": ("tularemia", "francisella tularensis"),
    "ebola": ("ebola", "ebola virus", "ebolavirus", "evd"),
    "marburg": ("marburg", "marburg virus"),
    "influenza_h5n1": ("h5n1", "avian influenza", "bird flu", "hpai"),
    "sars": ("sars", "sars-cov", "severe acute respiratory syndrome"),
    "cholera": ("cholera", "vibrio cholerae"),
    "mpox": ("mpox", "monkeypox", "mpxv"),
    "novel_respiratory": ("novel respiratory", "unknown pneumonia", "atypical pneumonia"),
}

SYMPTOM_KEYWORDS = (
    "hemorrhagic fever", "acute respiratory distress", "mass casualty",
    "unexplained deaths", "cluster of illness", "unusual disease",
    "syndromic surge", "respiratory failure cluster",
)

OUTBREAK_INDICATORS = (
    "outbreak", "epidemic", "pandemic", "public health emergency",
    "quarantine", "containment", "contact tracing", "case fatality",
)


def _compile_patterns() -> dict[str, re.Pattern[str]]:
    """Pre-compile regex patterns for each pathogen keyword group."""
    patterns: dict[str, re.Pattern[str]] = {}
    for pathogen, terms in PATHOGEN_KEYWORDS.items():
        escaped = [re.escape(t) for t in terms]
        patterns[pathogen] = re.compile(
            r"\b(?:" + "|".join(escaped) + r")\b", re.IGNORECASE
        )
    return patterns


PATHOGEN_PATTERNS = _compile_patterns()

SYMPTOM_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(s) for s in SYMPTOM_KEYWORDS) + r")\b",
    re.IGNORECASE,
)
OUTBREAK_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(o) for o in OUTBREAK_INDICATORS) + r")\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Sliding-window frequency tracker
# ---------------------------------------------------------------------------

@dataclass
class WindowStats:
    """Rolling statistics for a (region, pathogen) pair."""
    window_size: int = 24  # number of periods to retain
    counts: deque[float] = field(default_factory=lambda: deque(maxlen=24))

    @property
    def mean(self) -> float:
        if not self.counts:
            return 0.0
        return sum(self.counts) / len(self.counts)

    @property
    def std(self) -> float:
        if len(self.counts) < 2:
            return 1.0  # avoid division by zero; assume unit variance
        m = self.mean
        variance = sum((x - m) ** 2 for x in self.counts) / (len(self.counts) - 1)
        return max(math.sqrt(variance), 0.01)

    def z_score(self, current: float) -> float:
        return (current - self.mean) / self.std

    def push(self, value: float) -> None:
        self.counts.append(value)


# ---------------------------------------------------------------------------
# Agent implementation
# ---------------------------------------------------------------------------

class OsintIngestionAgent(BaseAgent):
    """Ingests text-based OSINT signals and detects NLP anomalies."""

    def __init__(
        self,
        bus: MessageBus,
        z_threshold: float = 2.5,
        min_keyword_hits: int = 2,
        agent_id: str = "osint_ingestion_01",
    ) -> None:
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.OSINT_INGESTION,
            bus=bus,
            cycle_interval=0.5,
        )
        self.z_threshold = z_threshold
        self.min_keyword_hits = min_keyword_hits
        self._input_queue: asyncio.Queue[Any] | None = None

        # Tracking: (region, pathogen) -> WindowStats
        self._freq_tracker: dict[tuple[str, str], WindowStats] = defaultdict(WindowStats)
        # Accumulator for the current cycle
        self._current_counts: dict[tuple[str, str], float] = defaultdict(float)

    async def start(self) -> None:
        self._input_queue = await self.bus.subscribe(
            Topics.RAW_SIGNALS, self.agent_id
        )
        await super().start()

    def score_text(self, text: str) -> list[RawSignal]:
        """Score a text against the keyword taxonomy.

        Returns a list of RawSignal objects, one per detected pathogen.
        """
        signals: list[RawSignal] = []
        text_lower = text.lower()

        for pathogen, pattern in PATHOGEN_PATTERNS.items():
            pathogen_hits = pattern.findall(text_lower)
            symptom_hits = SYMPTOM_PATTERN.findall(text_lower)
            outbreak_hits = OUTBREAK_PATTERN.findall(text_lower)

            total_hits = len(pathogen_hits) + len(symptom_hits) + len(outbreak_hits)
            if total_hits < self.min_keyword_hits:
                continue

            all_hits = tuple(pathogen_hits + symptom_hits + outbreak_hits)
            relevance = min(1.0, total_hits / 10.0)

            signals.append(RawSignal(
                source=SignalSource.NEWS,
                pathogen_hint=pathogen,
                keyword_hits=all_hits,
                raw_score=relevance,
            ))

        return signals

    async def _run_cycle(self) -> None:
        if self._input_queue is None:
            return

        batch: list[RawSignal] = []
        try:
            while True:
                signal = self._input_queue.get_nowait()
                if isinstance(signal, RawSignal):
                    batch.append(signal)
        except asyncio.QueueEmpty:
            pass

        for signal in batch:
            key = (signal.region or "global", signal.pathogen_hint or "unknown")
            self._current_counts[key] += signal.raw_score

            # Update frequency tracker and check for anomalies
            tracker = self._freq_tracker[key]
            current = self._current_counts[key]
            z = tracker.z_score(current)

            if z >= self.z_threshold and len(tracker.counts) >= 3:
                report = AnomalyReport(
                    originating_agent=AgentRole.OSINT_INGESTION,
                    region=key[0],
                    pathogen_hint=key[1],
                    anomaly_score=min(1.0, z / 5.0),
                    baseline_value=tracker.mean,
                    observed_value=current,
                    z_score=z,
                    contributing_signals=(signal.signal_id,),
                    explanation=(
                        f"OSINT mention frequency for '{key[1]}' in '{key[0]}' "
                        f"is {z:.2f} standard deviations above baseline "
                        f"(observed={current:.1f}, baseline_mean={tracker.mean:.1f})"
                    ),
                )
                await self.bus.publish(Topics.ANOMALY_REPORTS, report)
                self.logger.info(
                    "Anomaly detected: %s in %s (z=%.2f)", key[1], key[0], z,
                )

        # End of cycle: push accumulated counts into the window and reset
        for key, count in self._current_counts.items():
            self._freq_tracker[key].push(count)
        self._current_counts.clear()
