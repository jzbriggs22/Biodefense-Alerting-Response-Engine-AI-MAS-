"""
Tamper-resistant audit log.

Each entry is hash-chained: entry N includes the SHA-256 hash of entry N-1,
creating a Merkle-style integrity chain. Any modification to a historical
entry invalidates all subsequent hashes.

In production this would be backed by an append-only store (e.g. Amazon QLDB,
immudb, or a write-ahead log with cryptographic sealing). The in-memory
implementation preserves the same integrity guarantees for testing and
development.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from bare.schemas.events import AuditEntry

logger = logging.getLogger("bare.audit")

GENESIS_HASH = "0" * 64  # SHA-256 zero hash for the first entry


def _serialize_entry(entry: AuditEntry, prev_hash: str) -> str:
    """Deterministic serialization for hashing."""
    d = asdict(entry)
    d["timestamp"] = d["timestamp"].isoformat()
    d["agent"] = d["agent"].value
    d["_prev_hash"] = prev_hash
    return json.dumps(d, sort_keys=True, default=str)


def _compute_hash(serialized: str) -> str:
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass
class ChainedEntry:
    """An audit entry with its integrity chain hash."""
    entry: AuditEntry
    prev_hash: str
    entry_hash: str
    sequence: int


class AuditLog:
    """Append-only, hash-chained audit log."""

    def __init__(self) -> None:
        self._entries: list[ChainedEntry] = []
        self._lock = Lock()

    def append(self, entry: AuditEntry) -> ChainedEntry:
        with self._lock:
            prev_hash = (
                self._entries[-1].entry_hash if self._entries else GENESIS_HASH
            )
            serialized = _serialize_entry(entry, prev_hash)
            entry_hash = _compute_hash(serialized)
            chained = ChainedEntry(
                entry=entry,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
                sequence=len(self._entries),
            )
            self._entries.append(chained)
            logger.debug(
                "Audit entry #%d: agent=%s action=%s hash=%s",
                chained.sequence, entry.agent.value, entry.action, entry_hash[:12],
            )
            return chained

    def verify_integrity(self) -> tuple[bool, str]:
        """Verify the full chain. Returns (valid, message)."""
        with self._lock:
            if not self._entries:
                return True, "Empty log — trivially valid."

            for i, chained in enumerate(self._entries):
                expected_prev = (
                    self._entries[i - 1].entry_hash if i > 0 else GENESIS_HASH
                )
                if chained.prev_hash != expected_prev:
                    return False, f"Chain break at sequence {i}: prev_hash mismatch."

                serialized = _serialize_entry(chained.entry, chained.prev_hash)
                recomputed = _compute_hash(serialized)
                if recomputed != chained.entry_hash:
                    return False, f"Hash mismatch at sequence {i}: entry tampered."

            return True, f"Chain valid — {len(self._entries)} entries verified."

    @property
    def entries(self) -> list[ChainedEntry]:
        with self._lock:
            return list(self._entries)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
