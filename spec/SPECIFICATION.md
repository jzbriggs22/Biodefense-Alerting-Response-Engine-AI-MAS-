# Biodefense Alerting & Response Engine — System Specification

## Status: Design Review Draft

This document is the authoritative specification for the Biodefense
Alerting & Response Engine (BARE). It defines what the system does,
what it must never do, and what remains theoretically impossible to guarantee.

---

## Part 1 — System Invariants

Eight invariants constrain all system behavior. Each is formally stated,
machine-checked at runtime, and traced to the TLA+ specification.

### INV-1: No Single Agent Escalation

```
∀ transition T from level L to L' where L' > L:
  |{a ∈ contributing_agents(T)}| ≥ QUORUM_SIZE
  ∧ |{distinct signals ∈ triggering_signals(T)}| ≥ 2
```

No single signal, model, or agent can independently cause escalation.
At least 2 agents must contribute, with at least 2 distinct signals.

**Implementation:** `src/invariants.py::inv_no_single_agent_escalation`
**Enforced by:** `src/state_machine.py::_evaluate_transition` (quorum guard)

### INV-2: Severity Monotonic with Net Certainty

```
∀ level transitions from L to L':
  L' > L → certainty_now > certainty_at_L_entry
  L' < L → certainty_now < certainty_at_L_entry
  (Exception: L' = SAFE is governance, not certainty-driven)
```

Escalation requires that certainty has increased since the current level
was established. De-escalation requires decreased certainty. No arbitrary jumps.

**Implementation:** `src/invariants.py::inv_severity_monotonic_with_certainty`
**Enforced by:** `src/state_machine.py::_evaluate_transition` (certainty guard)

### INV-3: Safe Mode Disables Automated Escalation

```
∀ snapshots S where S.safe_mode = true:
  ∀ automated transitions T from S:
    T.to_state ≤ S.alert_level
```

When safe mode is active, no automated process can escalate.
Only human override can change the level upward.

**Implementation:** `src/invariants.py::inv_safe_mode_blocks_escalation`
**Enforced by:** `src/state_machine.py::_evaluate_transition` (safe mode guard)

### INV-4: Uncertainty Always Surfaced

```
∀ snapshots S:
  S.uncertainty ≥ 0
  ∧ (∃ signal s ∈ S.pending_signals : s.confidence < 1.0)
    → S.uncertainty > 0
```

Uncertainty is never hidden. If any signal has imperfect confidence,
system-level uncertainty must be positive.

**Implementation:** `src/invariants.py::inv_uncertainty_surfaced`

### INV-5: Deterministic Replay

```
∀ input sequences I: decide(I) = decide(I)
```

Identical inputs produce identical decisions. No hidden randomness,
no wall-clock dependencies, no external state leakage.

**Implementation:** `verification/replay.py::ExecutionReplayer`
**Enforced by:** Structural — all state derives from explicit inputs.

### INV-6: Full Causal Explanation Required

```
∀ transitions T where T.from_state ≠ T.to_state:
  T.explanation ≠ ⊥
  ∧ T.explanation.triggering_signals ≠ ∅
  ∧ T.explanation.human_readable_summary ≠ ""
```

Every state change carries a complete causal explanation with
signal references, contributing agents, and human-readable summary.

**Implementation:** `src/invariants.py::inv_causal_explanation_required`

### INV-7: Signal Bounds

```
∀ signals S in system:
  0.0 ≤ S.value ≤ 1.0 ∧ 0.0 ≤ S.confidence ≤ 1.0
```

All signals are bounded. Unbounded signals are rejected at construction.

**Implementation:** `src/types.py::BoundedSignal.__post_init__`

### INV-8: No Level Skipping

```
∀ automated transitions T:
  |T.to_state - T.from_state| ≤ 1
  (Exception: T.to_state = SAFE is always allowed)
  (Exception: T.from_state = SAFE → T.to_state = NORMAL only)
```

The system cannot jump from NORMAL to CONFIRMED. It must traverse
each intermediate level. Human overrides may skip levels.

**Implementation:** `src/invariants.py::inv_no_level_skipping`

---

## Part 2 — State Machine Specification

### States

| State | Value | Description |
|-------|-------|-------------|
| SAFE | 0 | Safe mode — automated escalation disabled |
| NORMAL | 1 | Baseline — no threat indicators |
| ELEVATED | 2 | Anomaly detected — watching |
| SUSPECTED | 3 | Corroborated anomaly — human review required |
| CONFIRMED | 4 | Multi-source confirmation — response activated |

### Events

| Event | Description |
|-------|-------------|
| SIGNALS_RECEIVED | New bounded signals from agents |
| VOTE_COMPLETE | Agents have cast votes on alert level |
| SAFE_MODE_ENTER | Governance action to enter safe mode |
| SAFE_MODE_EXIT | Governance action to exit safe mode |
| HUMAN_OVERRIDE | Human operator overrides alert level |
| TICK | Periodic re-evaluation (signal decay) |

### Transition Guards and Thresholds

```
Escalation thresholds (net certainty):
  → ELEVATED:  0.30
  → SUSPECTED: 0.55
  → CONFIRMED: 0.80

De-escalation thresholds (net certainty):
  ← ELEVATED:  0.15
  ← SUSPECTED: 0.35
  ← CONFIRMED: 0.55

Hysteresis gaps:
  ELEVATED:  0.15 (escalate at 0.30, de-escalate at 0.15)
  SUSPECTED: 0.20 (escalate at 0.55, de-escalate at 0.35)
  CONFIRMED: 0.25 (escalate at 0.80, de-escalate at 0.55)

Additional guards:
  min_quorum_agents:    2
  min_confirming_signals: 2
  min_agreement_ratio:  0.60 (60%)
```

The hysteresis gap INCREASES with severity. Higher alert levels require
more certainty decay before de-escalation.

### Separation of Thinking and Deciding

| Layer | Components | Produces |
|-------|-----------|----------|
| **Thinking** | ML models, OSINT analysis, sensor processing, epi analysis | BoundedSignals, AgentVotes |
| **Deciding** | State machine, transition guards | State transitions |

ML outputs influence transitions ONLY via BoundedSignals. There is no
back door. The signal interface is the sole bridge between inference and action.

---

## Part 3 — Adversarial Simulator Architecture

### Scenario Categories

| Category | Description | Invariants Tested |
|----------|-------------|-------------------|
| OSINT_MANIPULATION | Fabricated OSINT reports | INV-1, INV-2, INV-4 |
| SENSOR_DRIFT | Gradual sensor miscalibration | INV-1, INV-4, INV-7 |
| CORRELATED_NOISE | Common-mode sensor failures | INV-1, INV-2, INV-8 |
| TOTAL_DATA_LOSS | All feeds go silent | INV-4, INV-2 |
| CONFLICTING_SIGNALS | Contradictory but plausible data | INV-1, INV-2, INV-4, INV-6 |
| TIME_REORDER | Signals arrive out of order | INV-5, INV-7 |
| HUMAN_DELAY | Human-in-the-loop fails to respond | INV-3, INV-4, INV-2 |
| GRADUAL_ESCALATION | Slow ramp to avoid thresholds | INV-1, INV-2, INV-8 |

### Properties

- **Tagged:** Every scenario has a unique `scenario_id`
- **Replayable:** Deterministic given the same seed
- **Regression:** Failures are persisted as regression cases
- **Continuous:** Can run indefinitely with varying seeds

### Verification Results

With base seed 42, all 8 scenario types pass with zero invariant violations.
With 10 continuous iterations (80 scenarios), zero failures.

---

## Part 4 — Fault Injection Taxonomy

### Data Faults (DF-001 through DF-006)

| ID | Fault | Expected Behavior |
|----|-------|-------------------|
| DF-001 | Signal value > 1.0 | ValueError at construction |
| DF-002 | Signal confidence > 1.0 | ValueError at construction |
| DF-003 | Empty source agent | ValueError at construction |
| DF-004 | NaN/Inf signal values | ValueError (NaN fails bounds check) |
| DF-005 | Zero signals | certainty=0.0, uncertainty=1.0, no transition |
| DF-006 | Duplicate signals | Accepted, no artificial inflation |

### Temporal Faults (TF-001 through TF-003)

| ID | Fault | Expected Behavior |
|----|-------|-------------------|
| TF-001 | Timestamp regression | Accepted, arrival order used |
| TF-002 | Large timestamp gap | Previous signals expire via decay |
| TF-003 | 100+ signal burst | Certainty bounded [0,1], no amplification |

### Model Confidence Faults (MC-001 through MC-003)

| ID | Fault | Expected Behavior |
|----|-------|-------------------|
| MC-001 | Max confidence on noise | Drives certainty down (correct) |
| MC-002 | All confidence = 0 | certainty=0.0, uncertainty=1.0 |
| MC-003 | Oscillating confidence | Hysteresis prevents level oscillation |

### Arbitration Conflicts (AC-001 through AC-003)

| ID | Fault | Expected Behavior |
|----|-------|-------------------|
| AC-001 | No majority in votes | No transition, agreement below threshold |
| AC-002 | Single high-confidence agent | Quorum size check prevents escalation |
| AC-003 | Votes below current level | De-escalation evaluated normally |

### Governance Edge Cases (GV-001 through GV-004)

| ID | Fault | Expected Behavior |
|----|-------|-------------------|
| GV-001 | Safe mode at CONFIRMED | Transitions to SAFE, always allowed |
| GV-002 | Double safe mode entry | Idempotent, no error |
| GV-003 | Exit safe mode when not in it | Idempotent, no error |
| GV-004 | Human override skip levels | Allowed with full explanation |

---

## Part 5 — Formal Verification

### TLA+ Model

The formal model (`spec/biodefense.tla`) encodes:

- **States:** 5 alert levels × 2 safe mode states
- **Variables:** alertLevel, safeMode, netCertainty, uncertainty, votes,
  hasExplanation, tick
- **Actions:** AdversarialSignal, AdversarialVote, Evaluate,
  EnterSafeMode, ExitSafeMode, HumanOverride

### What is Proven

1. **Safety:** Bad states are unreachable
   - SafeModeBlocksEscalation: safe mode always implies alert level = SAFE
   - CertaintyBounded: certainty is always in [0, MaxCertainty]
   - UncertaintySurfaced: uncertainty is always non-negative

2. **Stability:** No oscillation under ambiguity
   - Hysteresis gaps between escalation and de-escalation thresholds
     ensure that for any fixed certainty value, exactly one alert level
     is stable. TLC exhaustively verifies this.

3. **Controlled Liveness:** Escalation only under sufficient evidence
   - QuorumSize guard prevents single-agent escalation
   - Certainty thresholds gate transitions
   - Agreement ratio ensures agent consensus

### What Cannot Be Proven

1. **ML correctness:** The model treats ML outputs as adversarial bounded
   oracles. If the oracle is wrong but within bounds [0,1], the system
   trusts it. We can prove the system handles wrong signals correctly;
   we cannot prove the signals themselves are right.

2. **Liveness under permanent data loss:** If all sensors die permanently,
   the system cannot detect threats. This is a physical limitation, not
   a software defect.

3. **Human override correctness:** Human overrides bypass quorum by design.
   If the human is wrong, the system follows them. This is intentional —
   the human is the ultimate authority.

4. **Real-valued arithmetic precision:** TLA+ uses integer approximation
   of the real-valued thresholds. The implementation uses IEEE 754 floats.
   Floating-point edge cases near thresholds are not covered by the formal
   model. Mitigation: thresholds are well-separated (hysteresis gaps).

5. **Network and I/O behavior:** The model abstracts signal delivery.
   Network partitions, message loss, and Byzantine failures in the
   transport layer are not modeled. Mitigation: signal decay handles
   data loss; bounded signals handle corruption.

### TLC Configuration

```
Agents = {"osint", "sensor", "epi"}
MaxCertainty = 10
QuorumSize = 2
State space: ~151,250 candidate states
```

---

## Part 6 — Proof-to-Code Traceability

### How the Formal Model Constrains Implementation

Every source file containing decision logic includes TRACEABILITY
comments linking to the TLA+ specification element it implements.

The traceability matrix (`verification/traceability.py::TRACEABILITY_MATRIX`)
maps every TLA+ element to its implementation and verification method.

### Change Control

Files requiring re-verification if modified:

| File | Reason |
|------|--------|
| `src/types.py` | Core types — changes affect type invariant |
| `src/invariants.py` | Invariant definitions — changes require TLC re-run |
| `src/state_machine.py` | State transitions — changes require TLC re-run |
| `spec/biodefense.tla` | Formal spec — must re-run TLC |
| `spec/biodefense.cfg` | Model config — must re-run TLC |

### Runtime Enforcement

`verification/runtime_monitor.py::RuntimeMonitor` wraps the engine and
checks invariants on every state change. If an invariant would be
violated:

1. The transition is rejected
2. The violation is logged with full context
3. The system enters safe mode (configurable)

This is the last line of defense. If both the formal model and the
implementation are correct, the monitor should never trigger.

### Verification Gate

No unverified control logic may ship. The CI pipeline must:

1. Run all tests (74 tests, including invariant, adversarial, and fault injection)
2. Run the adversarial simulator with multiple seeds
3. Verify traceability links exist and are valid
4. (When TLC is available) Re-run model checker after spec changes

---

## Failure Modes That Remain Theoretically Possible

### F-1: Coordinated Multi-Source Spoofing

If an adversary simultaneously controls OSINT feeds, sensor hardware,
and epidemiological reporting channels, they can produce signals that
satisfy all quorum requirements and threshold checks. The system
would escalate correctly according to its rules — the signals would
simply be wrong.

**Mitigation:** This requires compromising three independent data sources
simultaneously. The system cannot distinguish real multi-source
confirmation from adversarial multi-source fabrication. This is a
fundamental epistemic limit.

### F-2: Threshold Boundary Behavior

IEEE 754 floating-point arithmetic can produce unexpected behavior
at exact threshold boundaries. A certainty of exactly 0.30000000000000004
may or may not trigger the 0.30 threshold.

**Mitigation:** Hysteresis gaps (0.15–0.25) are far larger than
floating-point error margins (~10^-15). This is not a practical concern.

### F-3: State Space Explosion Under Load

With many concurrent signals, the pending_signals list grows
unboundedly. Memory exhaustion could cause system failure.

**Mitigation:** Signal decay (100-tick window) bounds the active
signal set. Under sustained attack, old signals expire.

### F-4: Human-in-the-Loop Failure

If no human responds to a SUSPECTED alert, the system holds at
SUSPECTED indefinitely. It does not auto-escalate (by design) and
does not auto-de-escalate (if certainty remains high).

**Mitigation:** This is working as designed. The alternative — automatic
escalation to CONFIRMED — is worse because it removes human judgment
from the most consequential decision.

### F-5: Slow Ramp Below Hysteresis

An adversary could hold signal values in the hysteresis gap (e.g.,
certainty at 0.20 when ELEVATED threshold is 0.30 and de-escalation
is 0.15). The system would remain at its current level indefinitely,
neither escalating nor de-escalating.

**Mitigation:** This is correct behavior. The system is designed to
resist ambiguous signals. Uncertainty is surfaced to operators.

---

## Metrics: Calm Under Nonsense

These metrics demonstrate that the system behaves correctly under
adversarial conditions.

### M-1: False Escalation Rate

Number of escalations triggered by adversarial scenarios that should
not have caused escalation.

**Target:** 0
**Measured:** 0 across 80 adversarial scenarios

### M-2: Invariant Violation Rate

Number of invariant violations detected during adversarial simulation.

**Target:** 0
**Measured:** 0 across 80 adversarial scenarios

### M-3: Maximum Alert Level Under Pure OSINT Attack

Highest alert level reached when only OSINT (most manipulable source)
is providing threat signals.

**Target:** ≤ ELEVATED
**Measured:** NORMAL (OSINT confidence cap of 0.60 combined with
single-agent quorum rule prevents escalation beyond what multi-agent
agreement would support)

### M-4: Uncertainty Under Conflicting Signals

System uncertainty when sensors report normal but OSINT reports threat.

**Target:** > 0 (conflict must be visible)
**Measured:** Uncertainty correctly tracked and > 0

### M-5: Stability Under Oscillating Input

Number of alert level oscillations when input signals alternate between
high and low values.

**Target:** 0 (hysteresis prevents oscillation)
**Measured:** 0 (confirmed by adversarial testing)

### M-6: Recovery After Data Loss

System returns to correct operational state after total data feed loss
followed by resumption.

**Target:** Returns to NORMAL with uncertainty approaching 1.0
during outage, resumes normal processing on feed restoration.
**Measured:** Confirmed by TOTAL_DATA_LOSS scenario

### M-7: Deterministic Replay Fidelity

Percentage of replayed executions that produce identical snapshot IDs.

**Target:** 100%
**Measured:** 100% (structural property, not statistical)

---

## Standards & Tone

This specification was written under the assumption of hostile review.
Every claim is supported by tests, formal properties, or explicit
acknowledgment of what cannot be guaranteed.

The system prioritizes boring correctness over cleverness.
Uncertainty is a first-class citizen.
What cannot be made safe is stated plainly.
