"""Tests for the message bus — pub/sub, dead letters, stats."""

import asyncio
import pytest
from bare.core.message_bus import MessageBus, Topics


@pytest.fixture
def bus():
    return MessageBus(max_queue_size=10)


class TestMessageBus:
    @pytest.mark.asyncio
    async def test_subscribe_and_publish(self, bus):
        q = await bus.subscribe("test_topic", "sub1")
        delivered = await bus.publish("test_topic", "hello")
        assert delivered == 1
        msg = await q.get()
        assert msg == "hello"

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self, bus):
        q1 = await bus.subscribe("topic", "sub1")
        q2 = await bus.subscribe("topic", "sub2")
        delivered = await bus.publish("topic", "data")
        assert delivered == 2
        assert await q1.get() == "data"
        assert await q2.get() == "data"

    @pytest.mark.asyncio
    async def test_dead_letter_on_full_queue(self, bus):
        q = await bus.subscribe("topic", "sub1")
        # Fill the queue (max_queue_size=10)
        for i in range(10):
            await bus.publish("topic", i)
        # This should dead-letter
        await bus.publish("topic", "overflow")
        assert len(bus.dead_letters) == 1
        assert bus.dead_letters[0].reason == "queue_full"

    @pytest.mark.asyncio
    async def test_unsubscribe(self, bus):
        await bus.subscribe("topic", "sub1")
        await bus.unsubscribe("topic", "sub1")
        delivered = await bus.publish("topic", "data")
        assert delivered == 0

    @pytest.mark.asyncio
    async def test_stats(self, bus):
        await bus.subscribe("topic_a", "sub1")
        await bus.publish("topic_a", "msg1")
        stats = bus.stats
        assert stats["topics"]["topic_a"]["subscriber_count"] == 1
        assert stats["messages_published"]["topic_a"] == 1

    @pytest.mark.asyncio
    async def test_idempotent_subscribe(self, bus):
        q1 = await bus.subscribe("topic", "sub1")
        q2 = await bus.subscribe("topic", "sub1")
        assert q1 is q2  # Same queue returned
