"""
Deterministic Replay for the Biodefense Alerting & Response Engine.

This module supports INV-5 (Deterministic Replay) by providing
infrastructure to record and replay system executions, verifying
that identical inputs produce identical outputs.

TRACEABILITY: spec/biodefense.tla :: INV-5
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from src.engine import BiodefenseEngine, EngineConfig
from src.agents.osint_agent import OSINTAgent
from src.agents.sensor_agent import SensorAgent
from src.agents.epi_agent import EpidemiologicalAgent
from src.invariants import inv_deterministic_replay, InvariantResult
from src.types import SystemSnapshot


# ---------------------------------------------------------------------------
# Execution Recording
# ---------------------------------------------------------------------------

@dataclass
class RecordedStep:
    """A single recorded step in an execution."""
    step_index: int
    action: str
    agent_id: Optional[str]
    data: Dict[str, Any]
    snapshot_id_after: str


@dataclass
class ExecutionRecord:
    """Complete record of an execution for replay."""
    record_id: str
    steps: List[RecordedStep]
    final_snapshot_id: str

    def to_json(self) -> str:
        return json.dumps({
            "record_id": self.record_id,
            "steps": [
                {
                    "step_index": s.step_index,
                    "action": s.action,
                    "agent_id": s.agent_id,
                    "data": s.data,
                    "snapshot_id_after": s.snapshot_id_after,
                }
                for s in self.steps
            ],
            "final_snapshot_id": self.final_snapshot_id,
        }, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "ExecutionRecord":
        d = json.loads(json_str)
        steps = [
            RecordedStep(
                step_index=s["step_index"],
                action=s["action"],
                agent_id=s.get("agent_id"),
                data=s["data"],
                snapshot_id_after=s["snapshot_id_after"],
            )
            for s in d["steps"]
        ]
        return cls(
            record_id=d["record_id"],
            steps=steps,
            final_snapshot_id=d["final_snapshot_id"],
        )


# ---------------------------------------------------------------------------
# Recorder
# ---------------------------------------------------------------------------

class ExecutionRecorder:
    """Records engine operations for later replay."""

    def __init__(self, record_id: str, engine: BiodefenseEngine):
        self._record_id = record_id
        self._engine = engine
        self._steps: List[RecordedStep] = []
        self._step_index = 0

    def record_ingest(self, agent_id: str, data: dict) -> None:
        self._engine.ingest(agent_id, data)
        self._steps.append(RecordedStep(
            step_index=self._step_index,
            action="ingest",
            agent_id=agent_id,
            data=data,
            snapshot_id_after=self._engine.snapshot.snapshot_id,
        ))
        self._step_index += 1

    def record_evaluate(self) -> None:
        self._engine.evaluate()
        self._steps.append(RecordedStep(
            step_index=self._step_index,
            action="evaluate",
            agent_id=None,
            data={},
            snapshot_id_after=self._engine.snapshot.snapshot_id,
        ))
        self._step_index += 1

    def record_tick(self) -> None:
        self._engine.tick()
        self._steps.append(RecordedStep(
            step_index=self._step_index,
            action="tick",
            agent_id=None,
            data={},
            snapshot_id_after=self._engine.snapshot.snapshot_id,
        ))
        self._step_index += 1

    def finish(self) -> ExecutionRecord:
        return ExecutionRecord(
            record_id=self._record_id,
            steps=list(self._steps),
            final_snapshot_id=self._engine.snapshot.snapshot_id,
        )


# ---------------------------------------------------------------------------
# Replayer
# ---------------------------------------------------------------------------

class ExecutionReplayer:
    """Replays a recorded execution and verifies determinism."""

    def replay(self, record: ExecutionRecord) -> Tuple[bool, List[str]]:
        """
        Replay a recorded execution against a fresh engine.

        Returns (all_match, list_of_mismatches).
        """
        engine = BiodefenseEngine(
            EngineConfig(enable_runtime_invariant_checks=True)
        )
        engine.register_agent(OSINTAgent())
        engine.register_agent(SensorAgent())
        engine.register_agent(EpidemiologicalAgent())

        mismatches: List[str] = []

        for step in record.steps:
            if step.action == "ingest" and step.agent_id:
                engine.ingest(step.agent_id, step.data)
            elif step.action == "evaluate":
                engine.evaluate()
            elif step.action == "tick":
                engine.tick()

            actual_snapshot_id = engine.snapshot.snapshot_id
            if actual_snapshot_id != step.snapshot_id_after:
                mismatches.append(
                    f"Step {step.step_index} ({step.action}): "
                    f"expected {step.snapshot_id_after}, "
                    f"got {actual_snapshot_id}"
                )

        final_match = engine.snapshot.snapshot_id == record.final_snapshot_id
        if not final_match:
            mismatches.append(
                f"Final snapshot: expected {record.final_snapshot_id}, "
                f"got {engine.snapshot.snapshot_id}"
            )

        return (len(mismatches) == 0, mismatches)
