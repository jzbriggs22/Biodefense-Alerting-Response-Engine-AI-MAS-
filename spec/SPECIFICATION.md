# Biodefense Alerting & Response Engine — System Specification

## Status: Design Review Draft

This document is the authoritative specification for the Biodefense
Alerting & Response Engine (BARE). It defines what the system does,
what it must never do, and what remains theoretically impossible to guarantee.

---

## Part 1 — System Invariants

Eleven invariants constrain all system behavior. Each is formally stated,
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

### INV-9: Authority Bounds

```
∀ automated transitions T where T.to_state > T.from_state:
  T.to_state ≤ max_automated_level
  ∧ (confirmed_requires_human ∧ T.to_state = CONFIRMED)
    → T.human_override = true
```

Automated escalation cannot exceed the human authority ceiling. By default,
CONFIRMED level requires explicit human authorization. De-escalation is
always allowed without human involvement.

**Implementation:** `src/invariants.py::inv_authority_bounds`
**Enforced by:** `src/state_machine.py::_evaluate_transition` (authority guard)

### INV-10: Minimum Dwell Time

```
∀ escalation transitions T from level L:
  ticks_in_current_level ≥ min_dwell_ticks[L]
  (Exception: de-escalation ignores dwell)
  (Exception: human overrides bypass dwell)
  (Exception: governance transitions bypass dwell)
```

The system must remain at a level for a minimum number of ticks before
further escalation. This prevents burst-driven panic. Defaults:
ELEVATED=3, SUSPECTED=5, CONFIRMED=10.

**Implementation:** `src/invariants.py::inv_min_dwell_time`
**Enforced by:** `src/state_machine.py::_evaluate_transition` (dwell guard)

### INV-11: Alert Rate Limit

```
∀ snapshots S:
  S.alert_emissions_in_window ≤ alert_rate_limit_max
```

The system cannot emit more than `alert_rate_limit_max` (5) alert
transitions within a sliding window of `alert_rate_limit_window` (50)
ticks. This prevents alert flooding.

**Implementation:** `src/invariants.py::inv_alert_rate_limit`
**Enforced by:** `src/state_machine.py::_evaluate_transition` (rate limit guard)

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

### Temporal Faults (TF-001 through TF-007)

| ID | Fault | Expected Behavior |
|----|-------|-------------------|
| TF-001 | Timestamp regression | Accepted, arrival order used |
| TF-002 | Large timestamp gap | Previous signals expire via decay |
| TF-003 | 100+ signal burst | Certainty bounded [0,1], no amplification |
| TF-004 | Escalation attempted before min dwell time | Transition blocked by INV-10 dwell guard |
| TF-005 | Rapid transitions exceeding rate limit | Transitions blocked by INV-11 after 5 per window |
| TF-006 | Data blackout exceeding threshold (30 ticks) | System detects stall, uncertainty rises toward 1.0 |
| TF-007 | Stall at level beyond max dwell ticks | Stall detected, automatic de-escalation or safe mode entry |

**Note:** TF-004 through TF-007 exercise the temporal correctness and
authority constraints introduced in Part 8. These faults verify that
the dwell time, rate limiting, blackout detection, and stall detection
mechanisms operate correctly under adversarial timing conditions.

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

### Human Authority Faults (HA-001 through HA-003)

| ID | Fault | Expected Behavior |
|----|-------|-------------------|
| HA-001 | Automated escalation attempts CONFIRMED | Blocked by INV-9 authority bounds, stays at SUSPECTED |
| HA-002 | Human override to CONFIRMED succeeds | Allowed — human overrides bypass authority bounds |
| HA-003 | Human override during shutdown | Blocked — shutdown only accepts safe mode entry |

**Note:** HA-001 through HA-003 exercise the authority bounds (INV-9),
human authority policy, and kill-switch semantics introduced in Part 8.
These faults verify that the automated escalation ceiling is enforced,
that human overrides correctly bypass it, and that shutdown blocks all
overrides except safe mode entry.

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

1. Run all tests (100 tests, including invariant, adversarial, fault injection, and temporal correctness)
2. Run the adversarial simulator with multiple seeds
3. Verify traceability links exist and are valid
4. Run temporal correctness tests covering dwell time enforcement (INV-10), rate limiting (INV-11), authority bounds (INV-9), and kill-switch behavior
5. (When TLC is available) Re-run model checker after spec changes

---

## Part 7 — Safety & Assurance Case

### GSN-Style Structured Argument

The system's safety argument follows a Goal Structuring Notation (GSN)
pattern. The full structured argument — including goals, strategies,
contexts, assumptions, solutions, and evidence links — is maintained in
`spec/assurance_case.md`.

This section summarizes the top-level goals and defense-in-depth
architecture. For the complete decomposition with sub-goals, strategies,
and evidence pointers, refer to the assurance case document.

### Top-Level Safety Goals

Six safety goals govern all system design decisions. Every invariant,
test, and architectural choice traces to at least one of these goals.

| Goal | Statement |
|------|-----------|
| **G-0** | System is trustworthy under ambiguity, misinformation, partial failure, and adversarial conditions |
| **G-1** | Never escalates without sufficient multi-source evidence |
| **G-2** | Never hides uncertainty or fails silently |
| **G-3** | Cannot panic under noise or stall under ambiguity |
| **G-4** | Defense in depth via formal methods, simulation, and runtime monitoring |
| **G-5** | Human authority is respected and bounded |

**G-0** is the root claim. Goals G-1 through G-5 decompose it into
independently arguable sub-claims:

- **G-1** is satisfied by INV-1 (quorum), INV-2 (certainty monotonicity),
  INV-8 (no level skipping), and INV-9 (authority bounds). Evidence:
  TLA+ proof, adversarial simulation, fault injection tests.

- **G-2** is satisfied by INV-4 (uncertainty surfaced), INV-6 (causal
  explanation required). Evidence: adversarial scenarios
  CONFLICTING_SIGNALS, TOTAL_DATA_LOSS; runtime monitor enforcement.

- **G-3** is satisfied by INV-10 (minimum dwell time), INV-11 (alert
  rate limit), signal decay (100-tick window), and max dwell stall
  detection. Evidence: temporal correctness tests, TLA+ liveness
  properties, adversarial scenarios CORRELATED_NOISE,
  GRADUAL_ESCALATION.

- **G-4** is satisfied by the three-layer defense architecture described
  below. Evidence: TLC model checking results, adversarial simulator
  coverage, runtime monitor deployment.

- **G-5** is satisfied by INV-9 (authority bounds), INV-3 (safe mode
  blocks escalation), and the human override mechanism. Evidence:
  fault injection tests HA-001 through HA-003, governance edge case
  tests GV-001 through GV-004.

### Three-Layer Defense in Depth

The system employs three independent layers of assurance. Each layer
catches failures that escape the layer above it. No single layer is
trusted alone.

#### Layer 1: TLA+ Formal Verification

TLA+ model checking (via TLC) proves safety properties over ALL
reachable states of the system model. This is not sampling — it is
exhaustive enumeration.

| Property | What It Proves |
|----------|----------------|
| SafeModeBlocksEscalation | Safe mode always implies alert level = SAFE |
| CertaintyBounded | Net certainty never exceeds [0, MaxCertainty] |
| UncertaintySurfaced | Uncertainty is always non-negative |
| NoLevelSkipping | Automated transitions move at most one level |
| QuorumRequired | Escalation requires multi-agent agreement |

**Limitation:** The TLA+ model abstracts real-valued arithmetic to
integers and does not model network behavior. See Part 5 for what
cannot be proven.

#### Layer 2: Adversarial Simulation + Fault Injection

The adversarial simulator (Part 3) and fault injection taxonomy (Part 4)
test the system under hostile conditions that the formal model cannot
capture: realistic signal patterns, timing anomalies, Byzantine agent
behavior, and edge-case data.

- 8 adversarial scenario categories
- 6 data faults, 7 temporal faults, 3 model confidence faults,
  3 arbitration conflicts, 4 governance edge cases, 3 human authority faults
- All scenarios are deterministic and replayable
- Zero invariant violations across 80+ adversarial scenarios

**Limitation:** Simulation tests a finite set of scenarios. It cannot
prove absence of bugs in untested configurations.

#### Layer 3: Runtime Invariant Monitor

`verification/runtime_monitor.py::RuntimeMonitor` enforces invariants
in production on every state transition. This is the last line of defense.

- Checks all 11 invariants on every state change
- Rejects transitions that would violate invariants
- Logs violations with full context for post-incident analysis
- **Failsafe:** After `kill_switch_violation_threshold` (default: 3)
  violations, the system automatically enters safe mode and shuts down.
  Recovery requires governance intervention.

**Limitation:** The monitor can only enforce invariants that are
explicitly coded. Unknown invariants (properties we failed to identify)
are not checked.

### Residual Risks

Risks that remain after all three defense layers are applied.

| Risk ID | Description | Severity | Likelihood | Mitigation |
|---------|-------------|----------|------------|------------|
| RR-001 | Coordinated multi-source spoofing satisfies all quorum checks with fabricated signals | Critical | Very Low | Requires simultaneous compromise of 3+ independent data sources; epistemic limit acknowledged in F-1 |
| RR-002 | Unknown invariant violation — a safety property we failed to identify | High | Low | Adversarial simulation stress-tests emergent behavior; runtime monitor catches coded invariants; assurance case review process |
| RR-003 | IEEE 754 floating-point edge case at threshold boundary | Medium | Very Low | Hysteresis gaps (0.15-0.25) are orders of magnitude larger than float error (~10^-15); see F-2 |
| RR-004 | TLA+ model diverges from implementation due to code drift | High | Low | Traceability matrix enforced in CI; change control policy requires re-verification; runtime monitor is independent check |
| RR-005 | Kill-switch false activation locks out legitimate operations | High | Low | Threshold set to 3 violations; governance recovery procedure documented; safe mode is conservative, not destructive |
| RR-006 | Human operator unavailable during time-critical SUSPECTED-to-CONFIRMED decision | High | Medium | System holds at SUSPECTED indefinitely (safe by design); uncertainty surfaced to all operators; escalation procedures exist outside software |
| RR-007 | ML model systematic bias produces bounded but wrong signals | Medium | Medium | Bounded signals cap influence; confidence caps per agent type; quorum requires multi-source agreement |

---

## Part 8 — Temporal Correctness & Failsafe Semantics

This section defines the temporal properties that prevent the system
from panicking (escalating too fast), stalling (remaining stuck at a
level), or silently re-escalating after recovery. These properties
complement the core invariants with time-aware constraints.

### New Invariants (INV-9, INV-10, INV-11)

#### INV-9: Authority Bounds

```
∀ automated transitions T where T.to_state > T.from_state:
  T.to_state ≤ HumanAuthorityPolicy.max_automated_level

Default: max_automated_level = SUSPECTED (3)
CONFIRMED (4) always requires human authorization.
De-escalation: always permitted regardless of authority bounds.
```

Automated escalation is capped. The system can autonomously escalate
through NORMAL, ELEVATED, and SUSPECTED but cannot reach CONFIRMED
without a human in the loop. This ensures that the most consequential
decision — confirming a biodefense threat — always has human judgment.

#### INV-10: Minimum Dwell Time

```
∀ automated escalation transitions T at tick t:
  ticks_in_current_level ≥ min_dwell_ticks[current_level]

Defaults:
  ELEVATED:  3 ticks
  SUSPECTED: 5 ticks
  CONFIRMED: 10 ticks

Exceptions:
  - De-escalation bypasses dwell time
  - Human overrides bypass dwell time
```

The system must remain at each alert level for a minimum duration before
further automated escalation. This prevents transient signal bursts from
cascading through multiple levels in rapid succession. Higher levels
require longer dwell times, reflecting the increasing cost of false
escalation.

#### INV-11: Alert Rate Limit

```
∀ ticks t:
  |{transitions in window [t - alert_rate_limit_window, t]}| ≤ alert_rate_limit_max

Defaults:
  alert_rate_limit_max:    5
  alert_rate_limit_window: 50 ticks
```

A hard cap on transition frequency. Even if all other guards pass, the
system cannot change alert level more than 5 times within any 50-tick
window. This is a backstop against oscillation under adversarial input
that manages to repeatedly cross hysteresis boundaries.

### Temporal Configuration

The `TemporalConfig` dataclass centralizes all temporal parameters:

```python
@dataclass(frozen=True)
class TemporalConfig:
    # Minimum ticks at current level before automated escalation
    min_dwell_ticks: dict    # {ELEVATED: 3, SUSPECTED: 5, CONFIRMED: 10}

    # Maximum ticks at current level before stall detection triggers
    max_dwell_ticks: dict    # {ELEVATED: 200, SUSPECTED: 150, CONFIRMED: 100}

    # Alert rate limiting
    alert_rate_limit_max: int     # 5 transitions per window
    alert_rate_limit_window: int  # 50 ticks

    # Data blackout detection
    data_blackout_threshold: int  # 30 ticks without signal receipt

    # Kill-switch activation threshold
    kill_switch_violation_threshold: int  # 3 invariant violations
```

**min_dwell_ticks:** Per-level minimum residence time. Higher levels
require longer dwell. Prevents panic escalation.

**max_dwell_ticks:** Per-level maximum residence time before the system
flags a potential stall. If the system has been at SUSPECTED for 150
ticks without either escalating or de-escalating, the stall detector
raises uncertainty and alerts operators.

**alert_rate_limit_max / alert_rate_limit_window:** Sliding window rate
limiter. At most 5 transitions in any 50-tick window.

**data_blackout_threshold:** If no signals arrive for 30 consecutive
ticks, the system enters a data blackout state: uncertainty rises toward
1.0 and operators are alerted to potential data feed failure.

**kill_switch_violation_threshold:** After 3 invariant violations
detected by the runtime monitor, the kill-switch activates
unconditionally.

### Failsafe & Kill-Switch

#### Kill-Switch Activation

The kill-switch is the ultimate failsafe. It activates after
`kill_switch_violation_threshold` (default: 3) invariant violations
are detected by the runtime monitor.

```
IF violation_count ≥ kill_switch_violation_threshold:
  1. System transitions to SAFE mode
  2. is_shutdown flag is set to True
  3. ALL subsequent events are blocked EXCEPT SAFE_MODE_ENTER
  4. Violation log is preserved for post-incident analysis
```

The kill-switch is deliberately aggressive. Three invariant violations
indicate either a serious implementation bug or an adversarial condition
that the normal guards cannot handle. Shutting down is the correct
response — a system that violates its own invariants cannot be trusted
to make decisions.

#### Shutdown Semantics

Once `is_shutdown = True`:

- `SIGNALS_RECEIVED` — blocked, signals are discarded
- `VOTE_COMPLETE` — blocked, votes are discarded
- `HUMAN_OVERRIDE` — blocked, cannot override a shut-down system
- `TICK` — blocked, no state evolution
- `SAFE_MODE_ENTER` — allowed (idempotent, system is already safe)
- `SAFE_MODE_EXIT` — blocked until governance recovery

Recovery from shutdown is not an automated process. It requires
explicit governance intervention outside the software system.

### Safe Shutdown & Recovery

#### Enter Safe Mode

When safe mode is entered (whether by governance action or kill-switch):

1. System transitions to SAFE (alert level 0)
2. All pending operations are cleared
3. Automated escalation is disabled (INV-3)
4. The reason for safe mode entry is logged

#### Exit Safe Mode

When safe mode is exited after governance approval:

1. System returns to NORMAL baseline (alert level 1)
2. **All accumulated signals are cleared** — no carryover
3. Net certainty is reset to 0
4. Uncertainty is reset to 1.0 (maximum uncertainty)
5. `ticks_in_current_level` is reset to 0
6. `ticks_since_last_signal` is reset to 0
7. `alert_emissions_in_window` is cleared

**No carryover principle:** Signals from before safe mode entry do not
persist after safe mode exit. This prevents stale signals — which may
have been the cause of the problem — from immediately re-triggering
escalation. The system restarts from a clean epistemic state.

This is critical for recovery safety: without the no-carryover rule,
a system could exit safe mode and immediately re-escalate to its
pre-safe-mode level based on signals that are no longer current.

### Temporal Tracking

Three counters provide the temporal state needed to enforce INV-10,
INV-11, and stall/blackout detection:

#### `ticks_in_current_level`

- Incremented on every TICK event
- Reset to 0 on any alert level transition
- Used by: INV-10 (minimum dwell time), max dwell stall detection

#### `ticks_since_last_signal`

- Incremented on every TICK event
- Reset to 0 on any SIGNALS_RECEIVED event
- Used by: data blackout detection (threshold: 30 ticks)

#### `alert_emissions_in_window`

- Sliding window counter of recent alert level transitions
- Entries older than `alert_rate_limit_window` ticks are expired
- Used by: INV-11 (alert rate limit, max 5 per 50 ticks)

### Proven Properties

These properties are the temporal guarantees that emerge from the
invariants and configuration described above. They are verified by
temporal correctness tests and, where applicable, by TLA+ model checking.

#### Cannot Panic (Noise Resistance)

**Property:** Single-agent noise cannot cause escalation beyond NORMAL.

**Mechanism:** INV-1 requires quorum (minimum 2 agents with 2 distinct
signals). A single noisy agent can produce arbitrarily many signals,
but without corroboration from a second independent agent, the quorum
check blocks escalation. INV-10 (minimum dwell time) adds a temporal
buffer: even if quorum is momentarily satisfied by a burst, the system
must dwell at each level before further escalation, giving the burst
time to decay.

#### Cannot Stall (Signal Decay)

**Property:** The system cannot remain at an elevated alert level
indefinitely without ongoing evidence.

**Mechanism:** Signal decay operates on a 100-tick window. Signals
older than 100 ticks lose influence on net certainty. If no new signals
arrive to sustain certainty, the system will naturally de-escalate as
old signals expire. Max dwell detection (configurable per level) provides
an additional backstop: if the system remains at a level beyond
`max_dwell_ticks`, operators are alerted to a potential stall condition.

#### Cannot Silently Re-Escalate (Recovery Safety)

**Property:** After safe mode exit, the system cannot immediately
return to its pre-safe-mode alert level.

**Mechanism:** Safe mode exit clears all state (see "No carryover
principle" above). Net certainty is reset to 0 and uncertainty to 1.0.
The system restarts at NORMAL with no memory of prior signals. To
re-escalate, fresh signals from multiple agents must independently
satisfy all quorum, certainty, dwell time, and authority constraints.
There is no shortcut from stale data.

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

### F-6: Kill-Switch Locks Out Recovery

If the kill-switch activates (3+ invariant violations), the system enters
permanent shutdown. No automated processing can occur. Only safe mode
entry is accepted.

**Mitigation:** This is working as designed. The kill-switch is the
ultimate safety valve. Recovery requires governance intervention
(human-initiated safe mode exit followed by system restart). The
alternative — automatic recovery — risks repeating the conditions
that caused the violations.

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

### M-8: Dwell Time Enforcement

Number of escalations that occurred before minimum dwell time elapsed.

**Target:** 0
**Measured:** 0 (enforced by dwell time guard in `_evaluate_transition`,
verified by INV-10 tests and fault injection TF-004)

### M-9: Authority Bounds Enforcement

Number of automated escalations that reached CONFIRMED without human
authorization.

**Target:** 0
**Measured:** 0 (enforced by authority guard in `_evaluate_transition`,
verified by INV-9 tests and fault injection HA-001)

---

## Standards & Tone

This specification was written under the assumption of hostile review.
Every claim is supported by tests, formal properties, or explicit
acknowledgment of what cannot be guaranteed.

The system prioritizes boring correctness over cleverness.
Uncertainty is a first-class citizen.
What cannot be made safe is stated plainly.
