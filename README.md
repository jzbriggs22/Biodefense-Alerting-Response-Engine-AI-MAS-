# BARE — Biodefense Alerting & Response Engine

A multi-agent system for real-time pathogen surveillance and emergency notification. Designed for public health agencies, hospital networks, and national security stakeholders.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SUPERVISOR / GOVERNANCE AGENT                        │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Arbitration │  │ Rate Limiter │  │ Human-in-the │  │ Tamper-Proof   │  │
│  │  Engine      │  │              │  │ -Loop Gate   │  │ Audit Log      │  │
│  └─────────────┘  └──────────────┘  └──────────────┘  └────────────────┘  │
└───────────────────────────────┬─────────────────────────────────────────────┘
                                │ monitors all agents via heartbeats
                                │ gates all alerts before release
    ┌───────────────────────────┼───────────────────────────┐
    │                           │                           │
    ▼                           ▼                           ▼
┌─────────┐  raw_signals  ┌──────────┐  anomaly_reports  ┌──────────────┐
│  OSINT  │──────────────▶│          │──────────────────▶│              │
│Ingestion│               │  MESSAGE │                   │Epidemiological│
│  Agent  │               │   BUS    │                   │  Reasoning   │
└─────────┘               │          │                   │    Agent     │
                          │ (Topics) │                   └──────┬───────┘
┌─────────┐               │          │                          │
│   IoT   │──────────────▶│          │                   epi_assessments
│  Sensor │  raw_signals  │          │                          │
│  Agent  │               │          │                          ▼
└─────────┘               │          │                   ┌──────────────┐
                          │          │◀──────────────────│    Threat    │
                          │          │ threat_assessments │Classification│
                          │          │                   │    Agent     │
                          │          │                   └──────────────┘
                          │          │
                          │          │    alerts          ┌──────────────┐
                          │          │◀──────────────────│   Response   │
                          │          │                   │Orchestration │
                          └──────────┘                   │    Agent     │
                                                         └──────────────┘
```

### Agent Interaction Flow

```
1. DATA INGESTION
   External Sources ──▶ [OSINT Agent] ──▶ RawSignal ──▶ Message Bus
   Sensor Feeds     ──▶ [IoT Agent]   ──▶ RawSignal ──▶ Message Bus

2. ANOMALY DETECTION
   RawSignal ──▶ [OSINT Agent: NLP keyword scoring + sliding-window z-test]
   RawSignal ──▶ [IoT Agent:  EMA baseline + seasonal decomposition + persistence check]
                          │
                          ▼
                   AnomalyReport ──▶ Message Bus

3. EPIDEMIOLOGICAL REASONING
   AnomalyReport(s) ──▶ [Epi Agent: Bayesian inference + SEIR projection]
                          │
                          ▼
                   EpiAssessment ──▶ Message Bus

4. THREAT CLASSIFICATION
   EpiAssessment ──▶ [Threat Agent: spatial/temporal/pathogen correlation]
                          │
                          ▼
                   ThreatAssessment ──▶ Message Bus

5. RESPONSE ORCHESTRATION
   ThreatAssessment ──▶ [Response Agent: playbook selection + alert generation]
                          │
                          ▼
                        Alert ──▶ Message Bus

6. GOVERNANCE
   Alert ──▶ [Supervisor: rate-limit check → confidence gate → human-hold gate]
                          │
                    ┌─────┴──────┐
                    ▼            ▼
              RELEASED      HELD (awaiting
            (auto-approved)  human review)
```

## Project Structure

```
bare/
├── __init__.py
├── main.py                          # Entry point and system runner
├── agents/
│   ├── osint_ingestion.py           # NLP-based OSINT anomaly detection
│   ├── iot_sensor.py                # Statistical sensor anomaly detection
│   ├── epi_reasoning.py             # Bayesian inference + SEIR models
│   ├── threat_classification.py     # Signal correlation + threat categorization
│   ├── response_orchestration.py    # Alert generation + playbook triggers
│   └── supervisor.py                # Governance, audit, human-in-the-loop
├── core/
│   ├── base_agent.py                # Abstract agent lifecycle management
│   ├── message_bus.py               # Async pub/sub with dead-letter tracking
│   └── audit.py                     # Hash-chained tamper-resistant audit log
├── schemas/
│   └── events.py                    # Immutable dataclass schemas for all events
├── config/
│   └── settings.py                  # Centralized system configuration
├── simulators/
│   └── outbreak_simulator.py        # Synthetic data generators for testing
├── playbooks/                       # (extensible) Response playbook definitions
└── tests/
    ├── conftest.py                  # Shared fixtures
    ├── test_schemas.py              # Schema immutability and defaults
    ├── test_message_bus.py          # Pub/sub, dead letters, stats
    ├── test_audit.py                # Chain integrity and tamper detection
    ├── test_agents.py               # Unit + integration tests for all agents
    └── test_simulator.py            # Signal generation and scenario validation
```

## Quick Start

```bash
# Install
pip install -e ".[test]"

# Run a scenario
python -m bare.main --scenario natural_gradual
python -m bare.main --scenario hostile_release
python -m bare.main --scenario multi_region_simultaneous
python -m bare.main --scenario baseline_noise

# Run tests
python -m pytest bare/tests/ -v
```

### Available Scenarios

| Scenario | Description |
|---|---|
| `baseline_noise` | Normal background noise with no outbreak — tests false-positive resistance |
| `natural_gradual` | Gradual cholera emergence in a single region |
| `natural_sudden` | Rapid Ebola onset in a single region |
| `multi_region_simultaneous` | Novel respiratory pathogen appearing in 3 US regions simultaneously |
| `hostile_release` | Anthrax detected in DC and NY — triggers hostile classification and maximum escalation |
| `false_alarm_seasonal` | Seasonal influenza spike with high noise — tests specificity |

## Core Data Schemas

All inter-agent data flows use frozen (immutable) dataclasses. Every object carries a UUID and UTC timestamp.

| Schema | Producer | Consumer | Key Fields |
|---|---|---|---|
| `RawSignal` | Simulators / External ingestion | OSINT Agent, IoT Agent | source, region, pathogen_hint, raw_score |
| `AnomalyReport` | OSINT Agent, IoT Agent | Epi Reasoning Agent | anomaly_score, z_score, baseline_value, explanation |
| `EpiAssessment` | Epi Reasoning Agent | Threat Classification Agent | r0_estimate, confidence, false_positive_prob, seir_parameters |
| `ThreatAssessment` | Threat Classification Agent | Response Orchestration Agent | category, severity, requires_human_escalation, correlation_factors |
| `Alert` | Response Orchestration Agent | Supervisor Agent | severity, playbook_id, recommended_actions, recipients, audit_chain |
| `AuditEntry` | Supervisor Agent | Immutable audit log | action, decision, rationale, input_ids, output_ids |

## Agent Design Details

### OSINT Ingestion Agent

**Anomaly detection approach:**
1. Incoming text signals are scored against a curated keyword taxonomy (pathogen names from CDC Category A/B, symptom descriptors, outbreak indicators).
2. A sliding-window frequency tracker maintains per-(region, pathogen) mention counts.
3. When current counts exceed the historical baseline by a configurable z-score threshold (default: 2.5σ), an `AnomalyReport` is emitted.

**Keyword taxonomy:** Maps pathogen names (anthrax, smallpox, plague, ebola, etc.) to regex patterns including common synonyms and scientific names. Symptom keywords include "hemorrhagic fever", "acute respiratory distress", "mass casualty", etc.

### IoT / Sensor Stream Agent

**Anomaly detection approach:**
1. Exponentially-weighted moving average (EMA) with configurable smoothing factor tracks baseline.
2. Seasonal offsets are learned and subtracted (default: 24-period daily cycle).
3. Deviations are measured in standard deviations from the de-seasonalized baseline.
4. A persistence gate requires N consecutive anomalous readings (default: 2) before reporting, reducing single-point false positives.

### Epidemiological Reasoning Agent

**Bayesian inference:**
- Prior: P(outbreak) = 0.001 per region per day (calibrated to historical WHO PHEIC frequency).
- Likelihood ratio per signal: exp(z_score), reflecting exponentially increasing likelihood under a real outbreak as signal strength grows.
- Multi-source corroboration bonus: multiplicative factor of ln(source_count).
- Posterior computed via log-odds Bayes' theorem for numerical stability.

**SEIR model:**
- Discrete-time compartmental model: Susceptible → Exposed → Infectious → Recovered.
- Transmission rate (β) scaled by anomaly magnitude.
- 14-day forward projection for R₀ estimation and doubling time computation.
- Population conservation invariant: S + E + I + R = 1.0 verified in tests.

### Threat Classification Agent

**Classification heuristics:**
- Pathogen profile: CDC Category A agents (anthrax, smallpox, plague, botulism, tularemia) carry elevated hostile priors (0.4).
- Spatial pattern: Multi-region simultaneous detection increases hostile score (natural outbreaks radiate from a focal point; simultaneous dispersed events are atypical).
- Source concordance: Agreement between independent source types (OSINT + sensors) multiplicatively increases confidence.
- Severity mapping: quantitative metrics → graduated levels (WATCH → ADVISORY → WARNING → EMERGENCY).
- Mandatory human escalation for WARNING/EMERGENCY severity or any hostile classification.

### Response Orchestration Agent

**Playbook library:**
| Playbook | Trigger | Recipients | Escalation Window |
|---|---|---|---|
| PB-001: Natural Watch | WATCH severity | Regional epi team | 24 hours |
| PB-002: Natural Advisory | ADVISORY severity | Epi team, hospitals, state health officer | 12 hours |
| PB-003: Natural Warning | WARNING severity | Epi team, hospitals, EMS, CDC EOC | 4 hours |
| PB-004: Hostile Emergency | Hostile classification | FBI WMD, DHS, CDC, hospitals, EMS, NBIC | 1 hour |
| PB-005: General Emergency | EMERGENCY (non-hostile) | CDC, hospitals, EMS, state, FEMA | 2 hours |

**Rate limiting:** Alerts are suppressed if another alert with the same (region, pathogen, severity) was issued within the cooldown period (default: 300s), preventing alert fatigue.

### Supervisor / Governance Agent

**Governance policies:**
- Hourly alert cap: 50 alerts/hour globally before output gating.
- Heartbeat monitoring: Agents are flagged as degraded if no heartbeat for 30s.
- Auto-release threshold: Alerts with confidence ≥ 0.7 and no human-hold flag are released automatically.
- Human-in-the-loop hold: All alerts with `requires_human_confirmation=True` are held until explicitly approved or rejected.
- Cannot fabricate alerts — can only suppress or hold them (defense-in-depth).

**Audit log:**
- SHA-256 hash chain: each entry includes the hash of the previous entry.
- Any modification to a historical entry invalidates all subsequent hashes.
- Integrity verification available on demand.

## Reliability & Safety

### No Single Point of Failure
- Each agent operates independently with its own lifecycle and error isolation.
- The message bus delivers to all subscribers; one failed consumer does not block others.
- Dead-letter tracking captures messages that could not be delivered.
- Agent health monitored via heartbeats; degraded agents are flagged but do not halt the system.

### Graceful Degradation

| Failure Mode | System Behavior | Impact |
|---|---|---|
| OSINT agent fails | IoT sensor agent continues independently; anomaly detection from sensors only | Reduced coverage — sensor-only detection |
| IoT sensor agent fails | OSINT agent continues; NLP-based detection only | Loss of quantitative sensor confirmation |
| Epi reasoning agent fails | Anomaly reports accumulate in message queue until recovery | Delayed assessment; no data loss if queue not full |
| Threat classification agent fails | Epi assessments queue; alerts paused | No new alerts until recovery; existing held alerts unaffected |
| Response agent fails | Threat assessments queue; supervisor continues monitoring | Alert generation paused; governance continues |
| Supervisor fails | Alerts generated but not governance-gated | Alerts bypass human review — degraded safety margin |
| Message bus queue full | Messages dead-lettered with tracking | Signal loss for affected subscribers; metrics visible |
| All agents fail except supervisor | System produces no alerts; audit log records agent timeouts | Complete detection outage; self-diagnosable |

### Deterministic Behavior
- Identical inputs produce identical anomaly scores, assessments, and alerts (verified in tests).
- Randomness is confined to the simulator layer and controlled via explicit seeds.
- Agent processing is deterministic given the same message ordering.

### Traceability
Every alert carries:
- `audit_chain`: ordered list of event IDs from signal → anomaly → assessment → threat → alert.
- `contributing_assessment_ids`: links to upstream assessments.
- `playbook_id`: which response playbook was triggered and why.
- All governance decisions (hold, release, suppress, approve, reject) are logged with rationale in the audit log.

## Security & Compliance

### Zero-Trust Architecture
- **Read-only ingestion:** External data sources are consumed through one-way channels. Agents never acknowledge or modify external sources.
- **Write-only alert output:** Alert generation is the sole write-path. No external system can query or modify internal state through the alert channel.
- **Agent isolation:** Each agent has access only to its subscribed topics. No agent can directly invoke another.
- **Supervisor-only governance:** Only the supervisor can hold, release, or suppress alerts.

### Data Minimization
- No PII is stored at any point in the pipeline.
- External references use opaque identifiers (article hashes, sensor serial numbers).
- Wearable and syndromic data is pre-aggregated before ingestion.
- Geographic resolution uses ISO 3166-1 codes, not GPS coordinates of individuals.

### Tamper-Resistant Logging
- SHA-256 hash-chained audit log — Merkle-style integrity.
- Append-only: no update or delete operations.
- Integrity verification detects any modification to historical entries.
- In production: backed by an append-only store (Amazon QLDB, immudb, or WAL with cryptographic sealing).

## Metrics

### Sensitivity
- **Hostile release scenario:** Both affected regions detected and classified as `potential_hostile` with `EMERGENCY` severity within the scenario timeline.
- **Natural gradual:** Detected after anomaly scores cross the z-threshold as signal accumulates past the baseline window.
- **Natural sudden:** Rapid onset detected within cycles of the signal spike.

### Specificity
- **Baseline noise scenario:** Zero false alerts generated across the full scenario duration.
- **False alarm seasonal:** Elevated noise with sub-threshold signals does not trigger alerts.
- **Persistence gating (IoT):** Single-point outliers are not reported.
- **Bayesian inference (Epi):** Low prior (0.001) combined with z-score-based likelihood ratios provides strong false-positive suppression.

### Latency
- **Pipeline latency:** Signal → Alert generation within agent cycle intervals (configurable, default 0.5-1.0s per agent).
- **End-to-end:** 5 agents × ~1 cycle each = approximately 5 processing cycles from signal to governance decision.
- **Rate limiting:** Configurable cooldown prevents duplicate alerts.

### Trustworthiness
- **Audit integrity:** Verifiable at any time. Chain validity checked post-scenario.
- **Explainability:** Every alert includes a human-readable narrative explaining the evidence chain, confidence score, false-positive probability, and playbook rationale.
- **Human-in-the-loop:** All EMERGENCY and hostile classifications require human confirmation before release.
- **Reproducibility:** Deterministic behavior under identical inputs, verified in test suite.

## Running Tests

```bash
# Full test suite (50 tests)
python -m pytest bare/tests/ -v

# Specific test files
python -m pytest bare/tests/test_agents.py -v       # Agent unit + integration
python -m pytest bare/tests/test_audit.py -v         # Audit log integrity
python -m pytest bare/tests/test_message_bus.py -v   # Pub/sub behavior
python -m pytest bare/tests/test_simulator.py -v     # Data generators
python -m pytest bare/tests/test_schemas.py -v       # Schema correctness
```

## Design Assumptions and Limitations

1. **Prior calibration:** The outbreak prior of 0.001 is derived from historical WHO PHEIC frequency. This should be recalibrated per deployment context (regional base rates, pathogen-specific priors).

2. **NLP simplification:** The keyword-matching approach is a structured approximation. Production systems would use transformer-based NER models trained on epidemiological corpora, with the keyword taxonomy as a fallback.

3. **SEIR simplification:** The discrete-time SEIR model uses fixed time steps and does not account for age-structure, spatial diffusion, or stochastic effects. It provides directional R₀ estimates, not precision epidemiological forecasts.

4. **Threat classification heuristics:** The hostile-vs-natural classification uses rule-based heuristics informed by CDC bioterrorism agent classifications. This is appropriate for initial triage but not for definitive attribution, which requires laboratory confirmation and intelligence analysis.

5. **In-process message bus:** The current implementation uses asyncio queues. Production deployment requires a persistent, distributed message broker (Kafka, NATS JetStream) for durability and horizontal scaling.

6. **Simulated data only:** The system operates on synthetic data generators. Production integration requires connectors to real OSINT feeds (WHO Disease Outbreak News, ProMED, CDC MMWR), sensor APIs, and hospital syndromic surveillance systems (BioSense Platform).
