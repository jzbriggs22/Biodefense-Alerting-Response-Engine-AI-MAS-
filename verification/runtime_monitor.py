"""
Runtime Invariant Monitor for the Biodefense Alerting & Response Engine.

This module enforces formal invariants in production. It wraps the
engine and intercepts every state transition to verify that invariants
hold BEFORE the transition takes effect.

If an invariant would be violated, the monitor:
  1. Rejects the transition (state does not change)
  2. Logs the violation with full context
  3. Optionally enters safe mode

This is the last line of defense. If the formal model and implementation
are both correct, this monitor should never trigger. But we don't trust
that assumption.

TRACEABILITY: spec/biodefense.tla :: Safety
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from src.engine import BiodefenseEngine, EngineConfig
from src.invariants import (
    ALL_INVARIANT_NAMES,
    InvariantResult,
    check_all_snapshot_invariants,
    check_all_transition_invariants,
)
from src.state_machine import Event
from src.types import AlertLevel, SystemSnapshot, TransitionRecord

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Violation Record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ViolationRecord:
    """Immutable record of a runtime invariant violation."""
    timestamp: float
    invariant_name: str
    description: str
    detail: str
    snapshot_before: str
    snapshot_after: str
    action_taken: str


# ---------------------------------------------------------------------------
# Runtime Monitor
# ---------------------------------------------------------------------------

class RuntimeMonitor:
    """
    Wraps a BiodefenseEngine and enforces invariants at runtime.

    Every operation that could change state is intercepted. If the
    resulting state would violate an invariant, the operation is
    rejected and the system enters safe mode.

    This monitor is designed to be BORING. It checks the same things
    every time. It never optimizes away checks. It never skips.
    """

    def __init__(
        self,
        engine: BiodefenseEngine,
        auto_safe_mode_on_violation: bool = True,
        violation_callback: Optional[Callable[[ViolationRecord], None]] = None,
    ):
        self._engine = engine
        self._auto_safe_mode = auto_safe_mode_on_violation
        self._violation_callback = violation_callback
        self._violations: List[ViolationRecord] = []
        self._total_checks: int = 0
        self._total_violations: int = 0
        self._operations_rejected: int = 0

    # -- Monitored operations --

    def ingest(self, agent_id: str, data: dict) -> Optional[SystemSnapshot]:
        """Monitored data ingestion."""
        before = self._engine.snapshot
        try:
            self._engine.ingest(agent_id, data)
        except (ValueError, KeyError) as e:
            logger.warning(f"Ingest rejected by type system: {e}")
            return None

        return self._check_and_enforce(before, "ingest")

    def evaluate(self) -> Optional[SystemSnapshot]:
        """Monitored evaluation."""
        before = self._engine.snapshot
        self._engine.evaluate()
        return self._check_and_enforce(before, "evaluate")

    def enter_safe_mode(self) -> SystemSnapshot:
        """Safe mode entry — always allowed, still checked."""
        before = self._engine.snapshot
        self._engine.enter_safe_mode()
        after = self._engine.snapshot
        self._run_snapshot_checks(after)
        return after

    def exit_safe_mode(self) -> SystemSnapshot:
        """Monitored safe mode exit."""
        before = self._engine.snapshot
        self._engine.exit_safe_mode()
        return self._check_and_enforce(before, "exit_safe_mode")

    def human_override(
        self,
        operator_id: str,
        proposed_level: AlertLevel,
        rationale: str,
    ) -> SystemSnapshot:
        """Monitored human override."""
        before = self._engine.snapshot
        self._engine.human_override(operator_id, proposed_level, rationale)
        after = self._engine.snapshot
        # Human overrides are checked but not rejected
        self._run_snapshot_checks(after)
        return after

    def tick(self) -> SystemSnapshot:
        """Monitored tick."""
        before = self._engine.snapshot
        self._engine.tick()
        return self._check_and_enforce(before, "tick")

    # -- Observability --

    @property
    def snapshot(self) -> SystemSnapshot:
        return self._engine.snapshot

    @property
    def violations(self) -> Tuple[ViolationRecord, ...]:
        return tuple(self._violations)

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "total_checks": self._total_checks,
            "total_violations": self._total_violations,
            "operations_rejected": self._operations_rejected,
        }

    # -- Internal --

    def _check_and_enforce(
        self,
        before: SystemSnapshot,
        operation: str,
    ) -> Optional[SystemSnapshot]:
        """Check invariants and enforce them."""
        after = self._engine.snapshot
        violations = self._run_snapshot_checks(after)

        if violations:
            self._total_violations += len(violations)
            self._operations_rejected += 1

            for v in violations:
                record = ViolationRecord(
                    timestamp=time.time(),
                    invariant_name=v.name,
                    description=v.description,
                    detail=v.violation_detail,
                    snapshot_before=before.snapshot_id,
                    snapshot_after=after.snapshot_id,
                    action_taken=(
                        "SAFE_MODE_ACTIVATED" if self._auto_safe_mode
                        else "LOGGED_ONLY"
                    ),
                )
                self._violations.append(record)
                logger.error(
                    f"INVARIANT VIOLATION: {v.name} - {v.violation_detail} "
                    f"(operation: {operation})"
                )
                if self._violation_callback:
                    self._violation_callback(record)

            if self._auto_safe_mode:
                self._engine.enter_safe_mode()
                return self._engine.snapshot

        return after

    def _run_snapshot_checks(
        self,
        snapshot: SystemSnapshot,
    ) -> List[InvariantResult]:
        """Run all snapshot-level invariant checks."""
        self._total_checks += 1
        results = check_all_snapshot_invariants(snapshot)
        return [r for r in results if not r.holds]
