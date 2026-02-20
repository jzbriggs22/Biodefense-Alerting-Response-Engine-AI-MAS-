"""
System-wide configuration for BARE.

All tunable parameters are centralized here. In production these
would be loaded from environment variables or a secrets manager
with appropriate access controls.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SystemConfig:
    """Top-level configuration for the BARE system."""

    # Message bus
    bus_max_queue_size: int = 4096

    # OSINT Ingestion Agent
    osint_z_threshold: float = 2.5
    osint_min_keyword_hits: int = 2
    osint_cycle_interval: float = 0.5

    # IoT Sensor Agent
    sensor_z_threshold: float = 3.0
    sensor_persistence_required: int = 2
    sensor_cycle_interval: float = 0.5

    # Epidemiological Reasoning Agent
    epi_confidence_threshold: float = 0.3
    epi_prior_outbreak: float = 0.001
    epi_cycle_interval: float = 1.0

    # Threat Classification Agent
    threat_cycle_interval: float = 1.0

    # Response Orchestration Agent
    response_rate_limit_seconds: float = 300.0
    response_cycle_interval: float = 1.0

    # Supervisor
    supervisor_max_alerts_per_hour: int = 50
    supervisor_heartbeat_timeout: float = 30.0
    supervisor_min_auto_release_confidence: float = 0.7

    # Simulation
    simulation_inter_cycle_delay: float = 0.1
    simulation_seed: int = 42

    # Logging
    log_level: str = "INFO"
    log_format: str = (
        "%(asctime)s | %(name)-30s | %(levelname)-8s | %(message)s"
    )


# Singleton default config
DEFAULT_CONFIG = SystemConfig()
