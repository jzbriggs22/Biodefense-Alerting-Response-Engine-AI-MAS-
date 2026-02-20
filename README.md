# Biodefense Alerting & Response Engine (BARE)

A flight-grade, multi-agent biodefense alerting system designed for
trustworthiness under ambiguity. Formally specified, adversarially
tested, and runtime-verified.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Engine (src/engine.py)            │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │  OSINT   │  │  Sensor  │  │ Epidemiological  │  │
│  │  Agent   │  │  Agent   │  │     Agent        │  │
│  └────┬─────┘  └────┬─────┘  └───────┬──────────┘  │
│       │              │                │              │
│       └──────────────┼────────────────┘              │
│                      ▼                               │
│            ┌─────────────────┐                       │
│            │ BoundedSignals  │  (value, confidence   │
│            │   [0.0, 1.0]   │   both bounded)       │
│            └────────┬────────┘                       │
│                     ▼                                │
│  ┌──────────────────────────────────────────────┐   │
│  │          State Machine (DECIDING)             │   │
│  │  SAFE ↔ NORMAL → ELEVATED → SUSPECTED →      │   │
│  │                   CONFIRMED                   │   │
│  │  Guards: quorum, certainty, agreement,        │   │
│  │          hysteresis, level-step               │   │
│  └──────────────────────────────────────────────┘   │
│                     ▼                                │
│  ┌──────────────────────────────────────────────┐   │
│  │      Runtime Invariant Monitor                │   │
│  │  8 invariants checked on every transition     │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Key Properties

- **No single agent can escalate** — quorum of 2+ agents required
- **Severity tracks certainty** — no escalation without increased evidence
- **Safe mode** — disables all automated escalation
- **Uncertainty is never hidden** — always explicitly tracked and surfaced
- **Deterministic replay** — identical inputs produce identical outputs
- **Full causal explanation** — every transition is explainable
- **No level skipping** — must traverse NORMAL → ELEVATED → SUSPECTED → CONFIRMED

## Project Structure

```
src/                    # Core system
  types.py              # Immutable types (BoundedSignal, AlertLevel, etc.)
  invariants.py         # 8 formal invariants as runtime predicates
  state_machine.py      # Deterministic FSM (the DECIDING layer)
  engine.py             # Top-level orchestrator
  agents/               # Agent implementations (the THINKING layer)

spec/                   # Formal specification
  biodefense.tla        # TLA+ model for verification
  biodefense.cfg        # TLC model checker configuration
  SPECIFICATION.md      # Complete system specification

adversarial/            # Continuous adversarial simulation
  scenarios.py          # 8 scenario generators
  simulator.py          # Adversarial simulation engine

fault_injection/        # Systematic fault injection
  framework.py          # 19 fault definitions across 5 categories

verification/           # Proof-to-code traceability
  runtime_monitor.py    # Runtime invariant enforcement
  traceability.py       # Formal model ↔ code mapping
  replay.py             # Deterministic replay infrastructure

tests/                  # 74 tests
  test_invariants.py    # Invariant predicate tests
  test_state_machine.py # FSM transition tests
  test_engine.py        # Integration tests
  test_adversarial.py   # Adversarial scenario tests
  test_fault_injection.py # Fault injection tests
```

## Running Tests

```bash
pip install pytest
PYTHONPATH=. pytest tests/ -v
```

## Design Principles

1. Boring correctness over cleverness
2. Uncertainty is a first-class citizen
3. What cannot be made safe is stated plainly
4. Thinking (ML/heuristics) is separated from Deciding (state transitions)
5. Assume hostile review
