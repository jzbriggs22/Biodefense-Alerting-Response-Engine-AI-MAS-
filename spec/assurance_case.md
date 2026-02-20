# Structured Assurance Case — Biodefense Alerting & Response Engine

## Format

This document uses a textual Goal Structuring Notation (GSN) style.
Each claim is numbered, linked to its supporting evidence or sub-claims,
and traceable to implementation artifacts.

---

## G-0: Top-Level Goal

**The Biodefense Alerting & Response Engine is trustworthy under ambiguity,
misinformation, partial failure, and adversarial conditions.**

Supported by: G-1, G-2, G-3, G-4

---

## G-1: The system never escalates without sufficient, multi-source evidence

### Strategy S-1: Structural prevention via invariants and guards

| Sub-claim | Evidence |
|-----------|----------|
| G-1.1: No single agent can trigger escalation | INV-1 (quorum of 2+ agents, 2+ distinct signals). Enforced structurally in `_evaluate_transition`. Verified by TLA+ `Evaluate` action requiring `nVoters >= QuorumSize`. |
| G-1.2: Escalation requires certainty increase since last level entry | INV-2 (severity monotonic with certainty). Guard in `_evaluate_transition`: `net_certainty > certainty_at_level_entry`. |
| G-1.3: No level skipping | INV-8 (one step at a time). Structural in `_evaluate_transition`: `target = current_level + 1`. TLA+: `majority = alertLevel + 1`. |
| G-1.4: Minimum dwell time before further escalation | INV-10 (configurable per-level minimum ticks). Guard in `_evaluate_transition`. |
| G-1.5: CONFIRMED requires human authorization | INV-9 (authority bounds). Default policy: `confirmed_requires_human=True`. |

### Residual risk

If an adversary simultaneously controls 2+ independent data sources (e.g.,
OSINT + sensors), they can produce signals that satisfy all quorum and
threshold requirements. The system would escalate correctly per its rules —
the signals are simply wrong. **This is a fundamental epistemic limit**, not
a software defect. Mitigation: requiring 2+ independent source types reduces
attack surface.

---

## G-2: The system never hides uncertainty or fails silently

### Strategy S-2: Uncertainty as first-class output

| Sub-claim | Evidence |
|-----------|----------|
| G-2.1: Uncertainty is always non-negative and explicitly tracked | INV-4. Checked on every snapshot and every transition. TLA+: `UncertaintySurfaced`. |
| G-2.2: Imperfect signals always produce positive uncertainty | INV-4: if any signal has `confidence < 1.0`, system uncertainty must be `> 0`. |
| G-2.3: Every state change carries full causal explanation | INV-6. `CausalExplanation` is required at construction (not optional). Includes signal references, agent attributions, and human-readable summary. |
| G-2.4: Data blackout is detected and surfaced | `TemporalConfig.data_blackout_threshold` flags loss of all feeds. Uncertainty approaches 1.0 during blackout. |
| G-2.5: Deterministic replay ensures auditability | INV-5. All state derives from explicit inputs. `ExecutionRecorder`/`ExecutionReplayer` verify identical outputs for identical inputs. |

### Residual risk

If the certainty aggregation function (`aggregate_certainty`) has a mathematical
error that consistently underestimates uncertainty, the system would report
false confidence. Mitigation: the function is deliberately simple
(confidence-weighted mean), and tested with property-based tests.

---

## G-3: The system cannot panic under noise or stall under ambiguity

### Strategy S-3: Temporal constraints and hysteresis

| Sub-claim | Evidence |
|-----------|----------|
| G-3.1: Hysteresis prevents oscillation | Escalation and de-escalation thresholds have a gap (0.15–0.25). For any fixed certainty, exactly one level is stable. TLC exhaustively verifies this across all reachable states. |
| G-3.2: Minimum dwell times prevent burst-driven panic | INV-10: ELEVATED requires 3 ticks, SUSPECTED requires 5 ticks before further escalation. |
| G-3.3: Alert rate limiting prevents flooding | INV-11: maximum 5 alerts per 50-tick window. Enforced in `_evaluate_transition`. |
| G-3.4: Signal decay resolves ambiguity over time | Signals older than 100 ticks are expired during `TICK` processing. Without fresh evidence, certainty decays toward 0, triggering de-escalation. |
| G-3.5: Maximum dwell time flags stall conditions | `TemporalConfig.max_dwell_ticks`: ELEVATED=200, SUSPECTED=150, CONFIRMED=100. Exceeding these flags a STALL condition for operator review. |
| G-3.6: Safe mode is always available as a halt | Any actor can enter SAFE mode at any time. SAFE mode is idempotent. |

### Residual risk

If signals arrive at exactly the hysteresis boundary (e.g., certainty
oscillating between 0.29 and 0.31 around the ELEVATED threshold of 0.30),
the system holds steady at its current level without oscillating, but the
operator receives no explicit notification of the boundary condition.
Mitigation: uncertainty tracking surfaces this implicitly.

---

## G-4: Formal methods, simulation, and runtime monitoring provide defense in depth

### Strategy S-4: Three independent verification layers

```
┌─────────────────────────────────────────────────────┐
│  Layer 1: Formal Verification (TLA+)                │
│  Proves safety over ALL reachable states             │
│  Catches: design errors, missing guards              │
├─────────────────────────────────────────────────────┤
│  Layer 2: Adversarial Simulation + Fault Injection   │
│  Tests behavior under hostile conditions             │
│  Catches: implementation bugs, edge cases            │
├─────────────────────────────────────────────────────┤
│  Layer 3: Runtime Invariant Monitor                  │
│  Enforces invariants in production                   │
│  Catches: anything the other layers missed           │
│  Failsafe: auto-safe-mode on violation               │
└─────────────────────────────────────────────────────┘
```

| Sub-claim | Evidence |
|-----------|----------|
| G-4.1: TLA+ model covers all state transitions | `spec/biodefense.tla` encodes Init, Next (6 actions), and Safety invariant. TLC configuration provided. |
| G-4.2: Adversarial simulator covers hostile scenarios | 8 scenario categories (OSINT manipulation, sensor drift, correlated noise, data loss, conflicting signals, time reordering, human delay, gradual escalation). 80+ scenarios tested with zero violations. |
| G-4.3: Fault injection covers assumption violations | 19 faults across 5 categories (data, temporal, confidence, arbitration, governance). All pass. |
| G-4.4: Runtime monitor enforces invariants in production | `RuntimeMonitor` intercepts every state change. Auto-enters SAFE mode on violation. Kill-switch after 3 violations. |
| G-4.5: Proof-to-code traceability is maintained | `TRACEABILITY_MATRIX` maps every TLA+ element to its implementation. Verification gate checks links on every build. |

### Residual risk

- **TLA+ uses integer approximation** of real-valued thresholds. Floating-point
  edge cases near exact threshold boundaries are not covered. Mitigation:
  hysteresis gaps (0.15–0.25) are orders of magnitude larger than float error.
- **The runtime monitor adds latency** to every state change. Mitigation:
  invariant checks are pure predicates over immutable snapshots — bounded
  and fast.

---

## G-5: Human authority is respected and bounded

### Strategy S-5: Explicit authority policy

| Sub-claim | Evidence |
|-----------|----------|
| G-5.1: Automated escalation cannot exceed SUSPECTED without human | INV-9, `HumanAuthorityPolicy.max_automated_level = SUSPECTED`. |
| G-5.2: Human overrides are fully logged with causal explanation | INV-6 applies to all transitions including human overrides. |
| G-5.3: Human overrides bypass quorum but not explanation | Structural in `_process_human_override`: quorum_met=True but CausalExplanation is still required. |
| G-5.4: Kill-switch provides ultimate fallback | `TemporalConfig.kill_switch_violation_threshold=3`. After 3 invariant violations, system enters SAFE mode and shuts down automated processing. Only safe mode entry is accepted. |

---

## Context and Assumptions

### C-1: Operating Environment

The system operates in an environment where:
- Data sources may be unreliable, delayed, or adversarially controlled
- Human operators may be slow to respond or make mistakes
- Network connectivity may be intermittent
- Sensor hardware may drift or fail

### C-2: Trust Boundaries

| Component | Trust Level |
|-----------|-------------|
| State machine logic | High — formally verified |
| Agent ML outputs | Low — treated as adversarial bounded oracles |
| OSINT data | Very low — confidence capped at 0.60 |
| Sensor data | Medium — confidence capped at 0.85 |
| Epi/lab data | High — confidence up to 0.95 |
| Human operators | Authoritative — can override but are logged |

### C-3: What This Assurance Case Does NOT Cover

1. Physical security of sensor hardware
2. Authentication and authorization of human operators
3. Network-level security (TLS, mutual auth, etc.)
4. Availability guarantees (uptime SLA)
5. Performance under extreme load (>10,000 signals/tick)

These are real concerns that require separate assurance arguments.

---

## Summary of Residual Risks

| Risk ID | Description | Severity | Likelihood | Mitigation |
|---------|-------------|----------|------------|------------|
| R-1 | Coordinated multi-source spoofing | High | Low | Quorum across independent source types |
| R-2 | Permanent data loss | High | Low | Uncertainty surfaces; system holds steady |
| R-3 | Human override error | Medium | Medium | Full logging; explanation required |
| R-4 | Float arithmetic at thresholds | Low | Very Low | Hysteresis gaps >> float epsilon |
| R-5 | ML model systematic bias | Medium | Medium | Bounded signals; confidence caps per agent type |
| R-6 | Kill-switch locks out recovery | Medium | Low | Safe mode entry always accepted; requires governance to restart |
