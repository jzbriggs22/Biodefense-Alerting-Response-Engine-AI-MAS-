"""
Supervisor / Governance Agent

The supervisor is the central authority for the BARE system. It:

    1. Monitors agent health via heartbeats
    2. Arbitrates disagreements between agents
    3. Enforces thresholds and rate-limiting policies
    4. Maintains the immutable audit log
    5. Implements human-in-the-loop checkpoints for high-severity events
    6. Provides system-wide observability

Design principles:
    - The supervisor does NOT make threat assessments itself. It
      validates and gates the outputs of specialized agents.
    - All decisions are logged with rationale for post-hoc review.
    - The supervisor can SUPPRESS alerts (false-positive override)
      but cannot FABRICATE them (defense-in-depth).
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from bare.core.audit import AuditLog
from bare.core.base_agent import AgentHealth, AgentState, BaseAgent
from bare.core.message_bus import MessageBus, Topics
from bare.schemas.events import (
    AgentRole,
    Alert,
    AuditEntry,
    SeverityLevel,
)


# ---------------------------------------------------------------------------
# Governance policies
# ---------------------------------------------------------------------------

# Maximum alerts per hour globally before the supervisor gates output
MAX_ALERTS_PER_HOUR = 50

# Agent heartbeat timeout — if an agent misses this many seconds of
# heartbeats, it is considered unhealthy.
HEARTBEAT_TIMEOUT_SECONDS = 30.0

# Minimum confidence for an alert to pass through without human hold
MIN_AUTO_RELEASE_CONFIDENCE = 0.7


class SupervisorAgent(BaseAgent):
    """System governance and audit authority."""

    def __init__(
        self,
        bus: MessageBus,
        audit_log: AuditLog,
        agent_id: str = "supervisor_01",
    ) -> None:
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.SUPERVISOR,
            bus=bus,
            cycle_interval=1.0,
            heartbeat_interval=10.0,
        )
        self.audit_log = audit_log
        self._alert_queue: asyncio.Queue[Any] | None = None
        self._heartbeat_queue: asyncio.Queue[Any] | None = None

        # Agent health tracking
        self._agent_health: dict[str, AgentHealth] = {}
        self._last_heartbeat_time: dict[str, datetime] = {}

        # Alert gating
        self._alerts_this_hour: list[datetime] = []
        self._held_alerts: list[Alert] = []
        self._released_alerts: list[Alert] = []
        self._suppressed_alerts: list[Alert] = []

    @property
    def system_status(self) -> dict[str, Any]:
        """Aggregate system health status."""
        now = datetime.now(timezone.utc)
        agents = {}
        for aid, health in self._agent_health.items():
            last_hb = self._last_heartbeat_time.get(aid)
            stale = (
                last_hb is not None
                and (now - last_hb).total_seconds() > HEARTBEAT_TIMEOUT_SECONDS
            )
            agents[aid] = {
                "role": health.role.value,
                "state": health.state.value,
                "stale_heartbeat": stale,
                "cycles": health.cycles_completed,
                "errors": health.errors_total,
            }
        return {
            "agents": agents,
            "alerts_released": len(self._released_alerts),
            "alerts_held": len(self._held_alerts),
            "alerts_suppressed": len(self._suppressed_alerts),
            "audit_entries": len(self.audit_log),
            "audit_integrity": self.audit_log.verify_integrity()[0],
        }

    async def start(self) -> None:
        self._alert_queue = await self.bus.subscribe(
            Topics.ALERTS, self.agent_id
        )
        self._heartbeat_queue = await self.bus.subscribe(
            Topics.AGENT_HEARTBEATS, self.agent_id
        )
        await super().start()

    async def _run_cycle(self) -> None:
        await self._process_heartbeats()
        await self._process_alerts()
        self._prune_hourly_counter()

    async def _process_heartbeats(self) -> None:
        if self._heartbeat_queue is None:
            return
        try:
            while True:
                hb = self._heartbeat_queue.get_nowait()
                if isinstance(hb, AgentHealth):
                    self._agent_health[hb.agent_id] = hb
                    self._last_heartbeat_time[hb.agent_id] = datetime.now(timezone.utc)
        except asyncio.QueueEmpty:
            pass

        # Check for stale agents
        now = datetime.now(timezone.utc)
        for aid, last_time in self._last_heartbeat_time.items():
            if (now - last_time).total_seconds() > HEARTBEAT_TIMEOUT_SECONDS:
                if self._agent_health[aid].state != AgentState.STOPPED:
                    self.logger.warning("Agent '%s' heartbeat stale — possible failure", aid)
                    self._record_audit(
                        action="heartbeat_timeout",
                        decision="flag_degraded",
                        rationale=f"Agent '{aid}' has not sent a heartbeat in "
                                  f"{HEARTBEAT_TIMEOUT_SECONDS}s",
                    )

    async def _process_alerts(self) -> None:
        if self._alert_queue is None:
            return

        try:
            while True:
                alert = self._alert_queue.get_nowait()
                if isinstance(alert, Alert):
                    self._gate_alert(alert)
        except asyncio.QueueEmpty:
            pass

    def _gate_alert(self, alert: Alert) -> None:
        """Apply governance policies to an incoming alert."""
        now = datetime.now(timezone.utc)

        # Rate-limit: suppress if hourly cap exceeded
        if len(self._alerts_this_hour) >= MAX_ALERTS_PER_HOUR:
            self._suppressed_alerts.append(alert)
            self._record_audit(
                action="alert_suppressed",
                input_ids=(alert.alert_id,),
                decision="rate_limited",
                rationale=f"Hourly alert cap ({MAX_ALERTS_PER_HOUR}) exceeded",
            )
            self.logger.warning("Alert %s suppressed — hourly rate limit", alert.alert_id)
            return

        # Human-in-the-loop hold for high severity or low confidence
        if alert.requires_human_confirmation:
            self._held_alerts.append(alert)
            self._record_audit(
                action="alert_held",
                input_ids=(alert.alert_id,),
                decision="human_review_required",
                rationale=(
                    f"Alert severity={alert.severity.value}, "
                    f"confidence={alert.confidence:.3f} — "
                    f"requires human confirmation before release"
                ),
            )
            self.logger.info(
                "Alert %s HELD for human review: %s", alert.alert_id, alert.headline,
            )
            return

        # Auto-release if confidence is sufficient
        if alert.confidence >= MIN_AUTO_RELEASE_CONFIDENCE:
            self._release_alert(alert)
        else:
            self._held_alerts.append(alert)
            self._record_audit(
                action="alert_held",
                input_ids=(alert.alert_id,),
                decision="low_confidence_hold",
                rationale=(
                    f"Confidence {alert.confidence:.3f} below auto-release "
                    f"threshold {MIN_AUTO_RELEASE_CONFIDENCE}"
                ),
            )

    def _release_alert(self, alert: Alert) -> None:
        """Release an alert to downstream consumers."""
        self._released_alerts.append(alert)
        self._alerts_this_hour.append(datetime.now(timezone.utc))
        self._record_audit(
            action="alert_released",
            input_ids=(alert.alert_id,),
            output_ids=(alert.alert_id,),
            decision="approved",
            rationale=(
                f"Alert meets governance criteria — severity={alert.severity.value}, "
                f"confidence={alert.confidence:.3f}, playbook={alert.playbook_id}"
            ),
        )
        self.logger.info(
            "Alert %s RELEASED: [%s] %s",
            alert.alert_id, alert.severity.value.upper(), alert.headline,
        )

    def approve_held_alert(self, alert_id: str, reviewer: str = "human_operator") -> bool:
        """Manually approve a held alert (human-in-the-loop checkpoint)."""
        for i, alert in enumerate(self._held_alerts):
            if alert.alert_id == alert_id:
                self._held_alerts.pop(i)
                self._release_alert(alert)
                self._record_audit(
                    action="manual_approval",
                    input_ids=(alert_id,),
                    decision="human_approved",
                    rationale=f"Manually approved by {reviewer}",
                )
                return True
        return False

    def reject_held_alert(self, alert_id: str, reviewer: str = "human_operator", reason: str = "") -> bool:
        """Reject a held alert (false positive determination)."""
        for i, alert in enumerate(self._held_alerts):
            if alert.alert_id == alert_id:
                self._held_alerts.pop(i)
                self._suppressed_alerts.append(alert)
                self._record_audit(
                    action="manual_rejection",
                    input_ids=(alert_id,),
                    decision="human_rejected",
                    rationale=f"Rejected by {reviewer}: {reason}",
                )
                return True
        return False

    def _prune_hourly_counter(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        self._alerts_this_hour = [
            t for t in self._alerts_this_hour if t > cutoff
        ]

    def _record_audit(
        self,
        action: str,
        decision: str,
        rationale: str,
        input_ids: tuple[str, ...] = (),
        output_ids: tuple[str, ...] = (),
    ) -> None:
        entry = AuditEntry(
            agent=AgentRole.SUPERVISOR,
            action=action,
            input_ids=input_ids,
            output_ids=output_ids,
            decision=decision,
            rationale=rationale,
        )
        self.audit_log.append(entry)
