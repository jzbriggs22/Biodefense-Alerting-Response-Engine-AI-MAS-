"""
In-process message bus for inter-agent communication.

Design rationale:
    - Topic-based pub/sub with type-safe channels
    - Async-first (asyncio) for non-blocking agent interaction
    - Bounded queues to prevent unbounded memory growth under load
    - Supports multiple subscribers per topic (fan-out)
    - Dead-letter tracking for dropped messages when queues are full

In a production deployment this would be backed by a persistent
message broker (e.g. Apache Kafka, NATS JetStream). The in-process
implementation preserves the same interface contract so agents
require no code changes when migrating.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("bare.message_bus")

DEFAULT_QUEUE_SIZE = 4096


@dataclass
class DeadLetter:
    """Record of a message that could not be delivered."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    topic: str = ""
    subscriber: str = ""
    reason: str = ""
    message_repr: str = ""


class MessageBus:
    """Async topic-based message bus with bounded queues.

    Usage:
        bus = MessageBus()
        queue = await bus.subscribe("anomaly_reports", "epi_agent")
        await bus.publish("anomaly_reports", some_report)
        msg = await queue.get()
    """

    def __init__(self, max_queue_size: int = DEFAULT_QUEUE_SIZE) -> None:
        self._max_queue_size = max_queue_size
        self._subscribers: dict[str, dict[str, asyncio.Queue[Any]]] = defaultdict(dict)
        self._dead_letters: list[DeadLetter] = []
        self._message_counts: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def subscribe(self, topic: str, subscriber_id: str) -> asyncio.Queue[Any]:
        """Register a subscriber and return its queue."""
        async with self._lock:
            if subscriber_id in self._subscribers[topic]:
                return self._subscribers[topic][subscriber_id]
            q: asyncio.Queue[Any] = asyncio.Queue(maxsize=self._max_queue_size)
            self._subscribers[topic][subscriber_id] = q
            logger.info("Subscriber '%s' registered on topic '%s'", subscriber_id, topic)
            return q

    async def unsubscribe(self, topic: str, subscriber_id: str) -> None:
        async with self._lock:
            self._subscribers[topic].pop(subscriber_id, None)

    async def publish(self, topic: str, message: Any) -> int:
        """Publish a message to all subscribers of a topic.

        Returns the number of subscribers that received the message.
        Messages are dropped (dead-lettered) for subscribers whose
        queues are full, rather than blocking the publisher.
        """
        delivered = 0
        async with self._lock:
            subscribers = dict(self._subscribers[topic])

        for sub_id, queue in subscribers.items():
            try:
                queue.put_nowait(message)
                delivered += 1
            except asyncio.QueueFull:
                dl = DeadLetter(
                    topic=topic,
                    subscriber=sub_id,
                    reason="queue_full",
                    message_repr=repr(message)[:200],
                )
                self._dead_letters.append(dl)
                logger.warning(
                    "Dead-lettered message on topic '%s' for subscriber '%s': queue full",
                    topic, sub_id,
                )

        self._message_counts[topic] += 1
        return delivered

    @property
    def dead_letters(self) -> list[DeadLetter]:
        return list(self._dead_letters)

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "topics": {
                topic: {
                    "subscriber_count": len(subs),
                    "subscribers": list(subs.keys()),
                }
                for topic, subs in self._subscribers.items()
            },
            "messages_published": dict(self._message_counts),
            "dead_letter_count": len(self._dead_letters),
        }


# ---------------------------------------------------------------------------
# Well-known topic names
# ---------------------------------------------------------------------------

class Topics:
    """Canonical topic names used across agents."""
    RAW_SIGNALS = "raw_signals"
    ANOMALY_REPORTS = "anomaly_reports"
    EPI_ASSESSMENTS = "epi_assessments"
    THREAT_ASSESSMENTS = "threat_assessments"
    ALERTS = "alerts"
    AUDIT_LOG = "audit_log"
    AGENT_HEARTBEATS = "agent_heartbeats"
    SUPERVISOR_COMMANDS = "supervisor_commands"
