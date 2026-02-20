"""Tests for the tamper-resistant audit log."""

import pytest
from bare.core.audit import AuditLog, ChainedEntry, GENESIS_HASH
from bare.schemas.events import AgentRole, AuditEntry


@pytest.fixture
def audit_log():
    return AuditLog()


class TestAuditLog:
    def test_empty_log_is_valid(self, audit_log):
        valid, msg = audit_log.verify_integrity()
        assert valid is True

    def test_single_entry(self, audit_log):
        entry = AuditEntry(
            agent=AgentRole.SUPERVISOR,
            action="test_action",
            decision="approved",
            rationale="unit test",
        )
        chained = audit_log.append(entry)
        assert chained.prev_hash == GENESIS_HASH
        assert chained.sequence == 0
        valid, _ = audit_log.verify_integrity()
        assert valid is True

    def test_chain_integrity(self, audit_log):
        for i in range(5):
            entry = AuditEntry(
                agent=AgentRole.SUPERVISOR,
                action=f"action_{i}",
                decision="logged",
                rationale=f"entry {i}",
            )
            audit_log.append(entry)

        assert len(audit_log) == 5
        valid, msg = audit_log.verify_integrity()
        assert valid is True
        assert "5 entries verified" in msg

    def test_hash_chaining(self, audit_log):
        e1 = AuditEntry(action="first")
        e2 = AuditEntry(action="second")
        c1 = audit_log.append(e1)
        c2 = audit_log.append(e2)
        assert c2.prev_hash == c1.entry_hash

    def test_tamper_detection(self, audit_log):
        for i in range(3):
            audit_log.append(AuditEntry(action=f"action_{i}"))

        # Tamper with the middle entry's hash
        audit_log._entries[1] = ChainedEntry(
            entry=audit_log._entries[1].entry,
            prev_hash=audit_log._entries[1].prev_hash,
            entry_hash="tampered_hash",
            sequence=1,
        )
        valid, msg = audit_log.verify_integrity()
        assert valid is False
