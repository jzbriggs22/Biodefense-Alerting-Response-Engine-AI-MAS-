"""
Main entry point for the BARE system.

Initializes all agents, wires them to the message bus, and runs
a configurable scenario end-to-end.

Usage:
    python -m bare.main                          # Default scenario
    python -m bare.main --scenario hostile_release
    python -m bare.main --scenario natural_sudden --seed 123
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from bare.agents.epi_reasoning import EpiReasoningAgent
from bare.agents.iot_sensor import IoTSensorAgent
from bare.agents.osint_ingestion import OsintIngestionAgent
from bare.agents.response_orchestration import ResponseOrchestrationAgent
from bare.agents.supervisor import SupervisorAgent
from bare.agents.threat_classification import ThreatClassificationAgent
from bare.config.settings import DEFAULT_CONFIG, SystemConfig
from bare.core.audit import AuditLog
from bare.core.message_bus import MessageBus
from bare.simulators.outbreak_simulator import (
    SCENARIOS,
    ScenarioRunner,
    ScenarioType,
)


def setup_logging(config: SystemConfig) -> None:
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format=config.log_format,
        stream=sys.stderr,
    )


def build_system(
    config: SystemConfig,
) -> tuple[MessageBus, AuditLog, list[Any], dict[str, Any]]:
    """Construct the full agent ensemble.

    Returns:
        (bus, audit_log, agents_list, agents_dict)
    """
    bus = MessageBus(max_queue_size=config.bus_max_queue_size)
    audit_log = AuditLog()

    osint = OsintIngestionAgent(
        bus=bus,
        z_threshold=config.osint_z_threshold,
        min_keyword_hits=config.osint_min_keyword_hits,
    )
    iot = IoTSensorAgent(
        bus=bus,
        z_threshold=config.sensor_z_threshold,
        persistence_required=config.sensor_persistence_required,
    )
    epi = EpiReasoningAgent(
        bus=bus,
        confidence_threshold=config.epi_confidence_threshold,
        prior=config.epi_prior_outbreak,
    )
    threat = ThreatClassificationAgent(bus=bus)
    response = ResponseOrchestrationAgent(
        bus=bus,
        rate_limit_seconds=config.response_rate_limit_seconds,
    )
    supervisor = SupervisorAgent(bus=bus, audit_log=audit_log)

    agents = [osint, iot, epi, threat, response, supervisor]
    agents_dict = {
        "osint": osint,
        "iot": iot,
        "epi": epi,
        "threat": threat,
        "response": response,
        "supervisor": supervisor,
    }

    return bus, audit_log, agents, agents_dict


async def run_scenario(
    scenario_type: ScenarioType,
    config: SystemConfig = DEFAULT_CONFIG,
    seed: int | None = None,
) -> dict[str, Any]:
    """Run a complete scenario and return results."""
    setup_logging(config)
    logger = logging.getLogger("bare.main")

    bus, audit_log, agents, agents_dict = build_system(config)

    scenario_config = SCENARIOS[scenario_type]
    runner = ScenarioRunner(
        bus=bus,
        config=scenario_config,
        seed=seed or config.simulation_seed,
    )

    logger.info("=" * 70)
    logger.info("BARE System — Biodefense Alerting & Response Engine")
    logger.info("Scenario: %s", scenario_type.value)
    logger.info("Pathogen: %s", scenario_config.pathogen)
    logger.info("Regions:  %s", ", ".join(scenario_config.regions))
    logger.info("Duration: %d cycles", scenario_config.duration_cycles)
    logger.info("=" * 70)

    # Start all agents
    agent_tasks = [asyncio.create_task(agent.start()) for agent in agents]

    # Give agents time to subscribe to topics
    await asyncio.sleep(0.5)

    # Run the scenario
    sim_results = await runner.run(
        inter_cycle_delay=config.simulation_inter_cycle_delay,
    )

    # Let the pipeline drain
    await asyncio.sleep(3.0)

    # Stop all agents
    for agent in agents:
        await agent.stop()

    # Wait for clean shutdown
    await asyncio.gather(*agent_tasks, return_exceptions=True)

    # Collect results
    supervisor = agents_dict["supervisor"]
    response_agent = agents_dict["response"]

    valid, integrity_msg = audit_log.verify_integrity()

    results = {
        "scenario": scenario_type.value,
        "simulation": sim_results,
        "system_status": supervisor.system_status,
        "alerts_generated": response_agent.alerts_generated,
        "alerts_suppressed_rate_limit": response_agent.alerts_suppressed,
        "alerts_released": len(supervisor._released_alerts),
        "alerts_held": len(supervisor._held_alerts),
        "alerts_suppressed_governance": len(supervisor._suppressed_alerts),
        "audit_entries": len(audit_log),
        "audit_integrity_valid": valid,
        "audit_integrity_message": integrity_msg,
        "bus_stats": bus.stats,
        "dead_letters": len(bus.dead_letters),
    }

    logger.info("=" * 70)
    logger.info("SCENARIO COMPLETE: %s", scenario_type.value)
    logger.info("Signals published:       %d", sim_results["signals_published"])
    logger.info("Alerts generated:        %d", response_agent.alerts_generated)
    logger.info("Alerts released:         %d", len(supervisor._released_alerts))
    logger.info("Alerts held (review):    %d", len(supervisor._held_alerts))
    logger.info("Alerts suppressed:       %d", len(supervisor._suppressed_alerts))
    logger.info("Audit entries:           %d", len(audit_log))
    logger.info("Audit chain integrity:   %s", integrity_msg)
    logger.info("Dead letters:            %d", len(bus.dead_letters))
    logger.info("=" * 70)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BARE — Biodefense Alerting & Response Engine",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="natural_gradual",
        choices=[s.value for s in ScenarioType],
        help="Scenario to run",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity",
    )
    args = parser.parse_args()

    config = SystemConfig(
        log_level=args.log_level,
        simulation_seed=args.seed or 42,
    )
    scenario = ScenarioType(args.scenario)
    asyncio.run(run_scenario(scenario, config, args.seed))


if __name__ == "__main__":
    main()
