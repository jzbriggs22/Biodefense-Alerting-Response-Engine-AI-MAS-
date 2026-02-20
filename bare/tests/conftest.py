"""Shared pytest fixtures for BARE tests."""

import pytest
from bare.core.audit import AuditLog
from bare.core.message_bus import MessageBus


@pytest.fixture
def message_bus():
    """Fresh message bus for each test."""
    return MessageBus(max_queue_size=256)


@pytest.fixture
def audit_log():
    """Fresh audit log for each test."""
    return AuditLog()
