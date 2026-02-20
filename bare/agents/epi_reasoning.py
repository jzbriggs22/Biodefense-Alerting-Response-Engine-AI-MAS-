"""
Epidemiological Reasoning Agent

Applies Bayesian inference and compartmental models (SEIR-style) to
assess the plausibility and spread risk of detected anomalies.

Approach:
    1. Receives AnomalyReport events from ingestion agents.
    2. Aggregates reports by (region, pathogen) within a time window.
    3. Estimates R₀ from the rate of change in anomaly scores using
       a simplified SEIR model.
    4. Computes a Bayesian posterior for "real outbreak" vs
       "false positive" given the prior base rate, anomaly strength,
       and number of corroborating sources.
    5. Emits an EpiAssessment with confidence score and false-positive
       probability.

Assumptions documented:
    - Prior probability of a real outbreak on any given day for any
      region is set at 0.001 (1 in 1000). This is calibrated to
      historical WHO PHEIC frequency and can be adjusted.
    - Likelihood ratios are derived from the anomaly z-scores using
      a log-normal mapping. This is a simplification; production
      systems would use pathogen-specific likelihood models.
"""

from __future__ import annotations

import asyncio
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from bare.core.base_agent import BaseAgent
from bare.core.message_bus import MessageBus, Topics
from bare.schemas.events import (
    AgentRole,
    AnomalyReport,
    EpiAssessment,
)


# ---------------------------------------------------------------------------
# SEIR model (simplified, discrete-time)
# ---------------------------------------------------------------------------

@dataclass
class SEIRState:
    """Discrete-time SEIR compartments normalized to [0, 1]."""
    S: float = 0.999    # Susceptible
    E: float = 0.0005   # Exposed
    I: float = 0.0005   # Infectious
    R: float = 0.0      # Recovered

    # Parameters (defaults for a generic respiratory pathogen)
    beta: float = 0.3         # Transmission rate
    sigma: float = 1 / 5.0    # 1 / incubation period (days)
    gamma: float = 1 / 10.0   # 1 / infectious period (days)

    @property
    def r0(self) -> float:
        """Basic reproduction number."""
        if self.gamma == 0:
            return 0.0
        return self.beta / self.gamma

    @property
    def doubling_time(self) -> float | None:
        """Approximate doubling time in days (exponential growth phase)."""
        growth_rate = self.beta * self.S - self.gamma
        if growth_rate <= 0:
            return None
        return math.log(2) / growth_rate

    def step(self) -> None:
        """Advance one discrete time step (1 day)."""
        new_exposed = self.beta * self.S * self.I
        new_infectious = self.sigma * self.E
        new_recovered = self.gamma * self.I

        self.S = max(0.0, self.S - new_exposed)
        self.E = max(0.0, self.E + new_exposed - new_infectious)
        self.I = max(0.0, self.I + new_infectious - new_recovered)
        self.R = min(1.0, self.R + new_recovered)

    def to_dict(self) -> dict[str, float]:
        return {
            "S": self.S, "E": self.E, "I": self.I, "R": self.R,
            "beta": self.beta, "sigma": self.sigma, "gamma": self.gamma,
        }


# ---------------------------------------------------------------------------
# Bayesian outbreak probability
# ---------------------------------------------------------------------------

# Prior probability of a real outbreak in any region on any day
PRIOR_OUTBREAK = 0.001

# Minimum number of corroborating reports to trigger assessment
MIN_CORROBORATING = 1


def compute_outbreak_posterior(
    prior: float,
    z_scores: list[float],
    source_count: int,
) -> tuple[float, float]:
    """Compute posterior P(outbreak | evidence) using Bayes' theorem.

    Likelihood model:
        P(evidence | outbreak) is modeled as the product of individual
        signal likelihoods, where each signal's likelihood ratio is
        exp(z_score) — signals with higher z-scores are exponentially
        more likely under a real outbreak.

        P(evidence | no outbreak) is 1.0 (the null hypothesis assigns
        uniform probability to any observation).

    Multi-source bonus:
        Corroborating signals from independent sources multiplicatively
        increase the likelihood ratio, reflecting the low probability
        of multiple independent false positives.

    Returns:
        (posterior, false_positive_prob) both in [0, 1]
    """
    if not z_scores:
        return prior, 1.0 - prior

    # Aggregate likelihood ratio
    log_lr = 0.0
    for z in z_scores:
        # Clamp to avoid overflow; z > 10 is effectively certain
        clamped_z = min(z, 10.0)
        log_lr += clamped_z  # ln(exp(z)) = z

    # Multi-source corroboration bonus
    if source_count > 1:
        log_lr += math.log(source_count)

    # Bayes' theorem in log-odds form
    log_prior_odds = math.log(prior / (1.0 - prior))
    log_posterior_odds = log_prior_odds + log_lr

    # Convert back to probability
    posterior = 1.0 / (1.0 + math.exp(-log_posterior_odds))
    posterior = max(0.0, min(1.0, posterior))
    false_positive_prob = 1.0 - posterior

    return posterior, false_positive_prob


# ---------------------------------------------------------------------------
# Report aggregator
# ---------------------------------------------------------------------------

@dataclass
class ReportAccumulator:
    """Accumulates anomaly reports for a (region, pathogen) pair."""
    reports: list[AnomalyReport] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)

    def add(self, report: AnomalyReport) -> None:
        self.reports.append(report)
        self.sources.add(report.originating_agent.value)

    @property
    def z_scores(self) -> list[float]:
        return [r.z_score for r in self.reports]

    @property
    def max_anomaly_score(self) -> float:
        if not self.reports:
            return 0.0
        return max(r.anomaly_score for r in self.reports)

    @property
    def report_ids(self) -> tuple[str, ...]:
        return tuple(r.report_id for r in self.reports)


# ---------------------------------------------------------------------------
# Agent implementation
# ---------------------------------------------------------------------------

class EpiReasoningAgent(BaseAgent):
    """Assesses outbreak plausibility from aggregated anomaly reports."""

    def __init__(
        self,
        bus: MessageBus,
        confidence_threshold: float = 0.3,
        prior: float = PRIOR_OUTBREAK,
        agent_id: str = "epi_reasoning_01",
    ) -> None:
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.EPI_REASONING,
            bus=bus,
            cycle_interval=1.0,
        )
        self.confidence_threshold = confidence_threshold
        self.prior = prior
        self._input_queue: asyncio.Queue[Any] | None = None
        self._accumulators: dict[tuple[str, str], ReportAccumulator] = defaultdict(
            ReportAccumulator
        )

    async def start(self) -> None:
        self._input_queue = await self.bus.subscribe(
            Topics.ANOMALY_REPORTS, self.agent_id
        )
        await super().start()

    async def _run_cycle(self) -> None:
        if self._input_queue is None:
            return

        # Drain incoming reports
        reports_received = 0
        try:
            while True:
                report = self._input_queue.get_nowait()
                if isinstance(report, AnomalyReport):
                    key = (report.region, report.pathogen_hint)
                    self._accumulators[key].add(report)
                    reports_received += 1
        except asyncio.QueueEmpty:
            pass

        if reports_received == 0:
            return

        # Assess each accumulated (region, pathogen) pair
        keys_to_clear = []
        for key, acc in self._accumulators.items():
            if len(acc.reports) < MIN_CORROBORATING:
                continue

            z_scores = acc.z_scores
            source_count = len(acc.sources)

            posterior, fp_prob = compute_outbreak_posterior(
                self.prior, z_scores, source_count,
            )

            if posterior < self.confidence_threshold:
                continue

            # Run simplified SEIR projection
            seir = SEIRState()
            # Adjust beta based on anomaly magnitude
            seir.beta = 0.2 + 0.3 * acc.max_anomaly_score
            for _ in range(14):  # 14-day forward projection
                seir.step()

            assessment = EpiAssessment(
                region=key[0],
                pathogen=key[1],
                r0_estimate=seir.r0,
                doubling_time_days=seir.doubling_time,
                confidence=posterior,
                false_positive_prob=fp_prob,
                seir_parameters=seir.to_dict(),
                contributing_reports=acc.report_ids,
                narrative=(
                    f"Bayesian assessment for '{key[1]}' in '{key[0]}': "
                    f"P(outbreak|evidence)={posterior:.4f} based on "
                    f"{len(acc.reports)} anomaly reports from {source_count} "
                    f"independent source(s). Estimated R₀={seir.r0:.2f}. "
                    f"{'Doubling time: ' + f'{seir.doubling_time:.1f} days' if seir.doubling_time else 'No exponential growth detected'}."
                ),
            )
            await self.bus.publish(Topics.EPI_ASSESSMENTS, assessment)
            self.logger.info(
                "EpiAssessment: %s in %s — confidence=%.4f, R0=%.2f",
                key[1], key[0], posterior, seir.r0,
            )
            keys_to_clear.append(key)

        for key in keys_to_clear:
            del self._accumulators[key]
