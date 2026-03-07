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
│  │  11 invariants checked on every transition    │   │
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
- **Authority bounds** — automation capped at SUSPECTED; CONFIRMED requires human
- **Minimum dwell time** — per-level minimum residence before escalation
- **Alert rate limiting** — max 5 transitions per 50 ticks

## Project Structure

```
src/                    # Core system
  types.py              # Immutable types (BoundedSignal, AlertLevel, etc.)
  invariants.py         # 11 formal invariants as runtime predicates
  state_machine.py      # Deterministic FSM (the DECIDING layer)
  engine.py             # Top-level orchestrator
  agents/               # Agent implementations (the THINKING layer)

spec/                   # Formal specification
  SPECIFICATION.md      # Complete system specification (Parts 1–8)
  assurance_case.md     # GSN-style safety assurance case
  biodefense.tla        # TLA+ model for verification
  biodefense.cfg        # TLC model checker configuration

adversarial/            # Continuous adversarial simulation
  scenarios.py          # 8 scenario generators
  simulator.py          # Adversarial simulation engine

fault_injection/        # Systematic fault injection
  framework.py          # 26 fault definitions across 7 categories

verification/           # Proof-to-code traceability
  runtime_monitor.py    # Runtime invariant enforcement
  traceability.py       # Formal model ↔ code mapping
  replay.py             # Deterministic replay infrastructure

tests/                  # 100 tests
  test_invariants.py    # Invariant predicate tests (28)
  test_state_machine.py # FSM transition tests (17)
  test_engine.py        # Integration tests (10)
  test_adversarial.py   # Adversarial scenario tests (10)
  test_fault_injection.py # Fault injection tests (9)
  test_temporal.py      # Temporal correctness & failsafe tests (26)

scripts/
  verify_gate.py        # 5-step verification gate orchestrator
```

## Quick Start

```bash
pip install -r requirements.txt
make test              # Run all 100 tests
make verify            # Run full 5-step verification gate
```

## Verification Gate

The verification gate (`make verify`) enforces 5 checks from the specification:

1. **All tests pass** — 100 tests across invariants, state machine, engine, adversarial, fault injection, and temporal correctness
2. **Adversarial simulator** — 8 scenario categories run with 5 seeds (42, 137, 256, 1000, 9999), zero invariant violations required
3. **Traceability links** — all TLA+ ↔ code mappings verified
4. **Temporal tests present** — `test_temporal.py` covers dwell time, rate limiting, authority bounds, and failsafe semantics
5. **TLC model checker** — runs if TLC is available, skipped with warning otherwise

Individual steps can be run via `python scripts/verify_gate.py --step <name>`.

## Design Principles

1. Boring correctness over cleverness
2. Uncertainty is a first-class citizen
3. What cannot be made safe is stated plainly
4. Thinking (ML/heuristics) is separated from Deciding (state transitions)
5. Assume hostile review
