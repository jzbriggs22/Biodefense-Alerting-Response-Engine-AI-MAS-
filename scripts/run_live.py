#!/usr/bin/env python3
"""
Live runner for the Biodefense Alerting & Response Engine.

Polls CDC NNDSS data on a configurable interval and feeds it through
the multi-agent engine pipeline.

Usage:
    python scripts/run_live.py                      # One-shot fetch + evaluate
    python scripts/run_live.py --poll 3600          # Poll every hour
    python scripts/run_live.py --year 2025 --weeks 8
    python scripts/run_live.py --dry-run             # Fetch only, no engine

Environment variables:
    CDC_APP_TOKEN   — Socrata app token for higher rate limits (optional)
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.adapters.cdc_nndss import (
    CDCNNDSSFetcher,
    normalize_for_epi_agent,
    normalize_for_osint_agent,
)
from src.agents.epi_agent import EpidemiologicalAgent
from src.agents.osint_agent import OSINTAgent
from src.agents.sensor_agent import SensorAgent
from src.engine import BiodefenseEngine, EngineConfig
from src.types import AlertLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bare.live")

# Graceful shutdown
_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    logger.info("Shutdown signal received, finishing current cycle...")
    _shutdown = True


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ---------------------------------------------------------------------------
# Engine setup
# ---------------------------------------------------------------------------

def build_engine() -> BiodefenseEngine:
    """Create and configure the engine with all agents."""
    engine = BiodefenseEngine(config=EngineConfig())
    engine.register_agent(OSINTAgent())
    engine.register_agent(SensorAgent())
    engine.register_agent(EpidemiologicalAgent())
    return engine


# ---------------------------------------------------------------------------
# Single cycle
# ---------------------------------------------------------------------------

def run_cycle(
    engine: BiodefenseEngine,
    fetcher: CDCNNDSSFetcher,
    tick: int,
    year: int | None = None,
    weeks_back: int = 4,
    dry_run: bool = False,
) -> None:
    """Execute one fetch-ingest-evaluate cycle."""
    logger.info("=" * 60)
    logger.info("CYCLE %d — Fetching CDC NNDSS data", tick)
    logger.info("=" * 60)

    result = fetcher.fetch_latest(year=year, weeks_back=weeks_back)

    if result.error:
        logger.error("Fetch failed: %s", result.error)
        logger.info("Engine remains at %s (no data ingested)", engine.snapshot.alert_level.name)
        return

    logger.info("Fetched %d records", len(result.records))

    # Log diseases found
    diseases_seen = {}
    for rec in result.records:
        if rec.current_week_count and rec.current_week_count > 0:
            diseases_seen[rec.disease] = diseases_seen.get(rec.disease, 0) + rec.current_week_count

    if diseases_seen:
        logger.info("Active diseases with reported cases:")
        for disease, count in sorted(diseases_seen.items(), key=lambda x: -x[1]):
            logger.info("  %s: %.0f cases", disease, count)
    else:
        logger.info("No cases reported for biodefense-relevant diseases")

    if dry_run:
        logger.info("[DRY RUN] Skipping engine ingestion")
        return

    # Normalize and ingest into both agents
    epi_data = normalize_for_epi_agent(result.records, timestamp=tick)
    osint_data = normalize_for_osint_agent(result.records, timestamp=tick)

    epi_signals = engine.ingest("epi_analyst", epi_data)
    osint_signals = engine.ingest("osint_monitor", osint_data)

    logger.info(
        "Ingested %d epi signals, %d osint signals",
        len(epi_signals), len(osint_signals),
    )

    # Tick to advance temporal tracking
    engine.tick()

    # Evaluate — agents vote, state machine decides
    snapshot = engine.evaluate()

    # Report
    logger.info("-" * 40)
    logger.info("ENGINE STATE:")
    logger.info("  Alert Level : %s", snapshot.alert_level.name)
    logger.info("  Safe Mode   : %s", snapshot.safe_mode)
    logger.info("  Certainty   : %.3f", snapshot.net_certainty)
    logger.info("  Uncertainty : %.3f", snapshot.uncertainty)
    logger.info("  Tick        : %d", snapshot.tick)

    if snapshot.last_explanation:
        logger.info("  Explanation : %s", snapshot.last_explanation.human_readable_summary)

    violations = engine.invariant_violations
    if violations:
        logger.warning("INVARIANT VIOLATIONS: %d", len(violations))
        for v in violations:
            logger.warning("  %s", v)

    if snapshot.alert_level >= AlertLevel.ELEVATED:
        logger.warning(
            "ALERT: Level %s — review recommended",
            snapshot.alert_level.name,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="BARE Live Runner — CDC NNDSS Integration"
    )
    parser.add_argument(
        "--poll", type=int, default=0,
        help="Poll interval in seconds (0 = one-shot, default: 0)",
    )
    parser.add_argument(
        "--year", type=int, default=None,
        help="NNDSS reporting year (default: current year)",
    )
    parser.add_argument(
        "--weeks", type=int, default=4,
        help="Weeks of history to fetch (default: 4)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Fetch data but don't feed to engine",
    )
    args = parser.parse_args()

    app_token = os.environ.get("CDC_APP_TOKEN")
    fetcher = CDCNNDSSFetcher(app_token=app_token)
    engine = build_engine()

    logger.info("BARE Live Runner started")
    logger.info("  Registered agents: %s", engine.registered_agents)
    logger.info("  Poll interval: %s", f"{args.poll}s" if args.poll else "one-shot")

    tick = 0
    run_cycle(engine, fetcher, tick, year=args.year, weeks_back=args.weeks, dry_run=args.dry_run)

    if args.poll > 0:
        while not _shutdown:
            for _ in range(args.poll):
                if _shutdown:
                    break
                time.sleep(1)
            if _shutdown:
                break
            tick += 1
            run_cycle(engine, fetcher, tick, year=args.year, weeks_back=args.weeks, dry_run=args.dry_run)

    logger.info("BARE Live Runner stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
