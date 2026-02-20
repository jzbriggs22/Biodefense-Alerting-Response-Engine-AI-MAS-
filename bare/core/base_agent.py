"""
Abstract base class for all BARE agents.

Provides:
    - Lifecycle management (start / stop / health)
    - Heartbeat emission
    - Structured logging
    - Graceful shutdown signaling
    - Error isolation (an unhandled exception in an agent does not
      crash the supervisor)

Every concrete agent must implement `_run_cycle()`, which is called
repeatedly by the base class run loop.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from bare.core.message_bus import MessageBus, Topics
from bare.schemas.events import AgentRole


class AgentState(Enum):
    IDLE = "idle"
    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass
class AgentHealth:
    """Snapshot of agent health for monitoring."""
    agent_id: str = ""
    role: AgentRole = AgentRole.SUPERVISOR
    state: AgentState = AgentState.IDLE
    last_heartbeat: datetime | None = None
    cycles_completed: int = 0
    errors_total: int = 0
    last_error: str = ""
    uptime_seconds: float = 0.0


class BaseAgent(ABC):
    """Base class for BARE agents.

    Subclasses implement `_run_cycle()` which is invoked repeatedly.
    The base class handles:
        - Async lifecycle
        - Heartbeat publishing
        - Error counting and state transitions
        - Graceful shutdown via `stop()`
    """

    def __init__(
        self,
        agent_id: str,
        role: AgentRole,
        bus: MessageBus,
        cycle_interval: float = 1.0,
        heartbeat_interval: float = 5.0,
    ) -> None:
        self.agent_id = agent_id
        self.role = role
        self.bus = bus
        self.cycle_interval = cycle_interval
        self.heartbeat_interval = heartbeat_interval

        self._state = AgentState.IDLE
        self._stop_event = asyncio.Event()
        self._cycles = 0
        self._errors = 0
        self._last_error = ""
        self._start_time: float | None = None
        self.logger = logging.getLogger(f"bare.agent.{agent_id}")

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def health(self) -> AgentHealth:
        uptime = time.monotonic() - self._start_time if self._start_time else 0.0
        return AgentHealth(
            agent_id=self.agent_id,
            role=self.role,
            state=self._state,
            last_heartbeat=datetime.now(timezone.utc),
            cycles_completed=self._cycles,
            errors_total=self._errors,
            last_error=self._last_error,
            uptime_seconds=uptime,
        )

    async def start(self) -> None:
        """Run the agent until `stop()` is called."""
        self._state = AgentState.RUNNING
        self._start_time = time.monotonic()
        self.logger.info("Agent '%s' (%s) starting", self.agent_id, self.role.value)

        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        try:
            await self._main_loop()
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass
            self._state = AgentState.STOPPED
            self.logger.info("Agent '%s' stopped", self.agent_id)

    async def stop(self) -> None:
        """Signal the agent to stop gracefully."""
        self.logger.info("Stop requested for agent '%s'", self.agent_id)
        self._stop_event.set()

    @abstractmethod
    async def _run_cycle(self) -> None:
        """Execute one processing cycle.

        Implementations should:
            1. Read from their subscribed queues (non-blocking)
            2. Process data
            3. Publish results to output topics
        """

    async def _main_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await self._run_cycle()
                self._cycles += 1
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._errors += 1
                self._last_error = f"{type(exc).__name__}: {exc}"
                self.logger.error(
                    "Error in cycle %d: %s", self._cycles, self._last_error,
                    exc_info=True,
                )
                if self._errors > 10 and self._errors > self._cycles * 0.5:
                    self._state = AgentState.DEGRADED
                    self.logger.warning("Agent '%s' entering DEGRADED state", self.agent_id)
            await asyncio.sleep(self.cycle_interval)

    async def _heartbeat_loop(self) -> None:
        while not self._stop_event.is_set():
            await self.bus.publish(Topics.AGENT_HEARTBEATS, self.health)
            await asyncio.sleep(self.heartbeat_interval)
