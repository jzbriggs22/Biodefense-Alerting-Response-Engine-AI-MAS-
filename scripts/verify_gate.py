#!/usr/bin/env python3
"""
Verification Gate for the Biodefense Alerting & Response Engine.

Implements the 5-step verification gate from SPECIFICATION.md Part 6:
  1. Run all tests
  2. Run adversarial simulator with multiple seeds
  3. Verify traceability links
  4. Confirm temporal correctness tests exist
  5. Run TLC model checker (conditional — skipped if TLC unavailable)

Usage:
    python scripts/verify_gate.py           # Run full gate
    python scripts/verify_gate.py --step tests
    python scripts/verify_gate.py --step adversarial
    python scripts/verify_gate.py --step traceability
    python scripts/verify_gate.py --step temporal
    python scripts/verify_gate.py --step tlc
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------

def step_tests() -> bool:
    """Step 1: Run all tests via pytest."""
    print("\n" + "=" * 60)
    print("STEP 1: Running all tests")
    print("=" * 60)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short"],
        cwd=str(PROJECT_ROOT),
    )
    return result.returncode == 0


def step_adversarial() -> bool:
    """Step 2: Run adversarial simulator with 5 seeds."""
    print("\n" + "=" * 60)
    print("STEP 2: Running adversarial simulator (5 seeds)")
    print("=" * 60)

    from adversarial.simulator import AdversarialSimulator

    seeds = [42, 137, 256, 1000, 9999]
    regression_dir = tempfile.mkdtemp(prefix="bare_regression_")
    sim = AdversarialSimulator(regression_dir=regression_dir)

    total_scenarios = 0
    total_passed = 0
    total_failed = 0

    for seed in seeds:
        results = sim.run_all_scenarios(base_seed=seed)
        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed)
        total_scenarios += len(results)
        total_passed += passed
        total_failed += failed
        status = "PASS" if failed == 0 else "FAIL"
        print(f"  Seed {seed:>5d}: {passed}/{len(results)} passed  [{status}]")

        if failed > 0:
            for r in results:
                if not r.passed:
                    print(f"    FAILED: {r.scenario_id} — {r.actual_behavior}")

    # Clean up temp dir
    shutil.rmtree(regression_dir, ignore_errors=True)

    print(f"\n  Total: {total_passed}/{total_scenarios} scenarios passed")
    return total_failed == 0


def step_traceability() -> bool:
    """Step 3: Verify traceability links."""
    print("\n" + "=" * 60)
    print("STEP 3: Verifying traceability links")
    print("=" * 60)

    from verification.traceability import verify_traceability_links

    statuses = verify_traceability_links(project_root=str(PROJECT_ROOT))
    all_passed = True
    for s in statuses:
        icon = "PASS" if s.passed else "FAIL"
        print(f"  [{icon}] {s.check_name}: {s.detail}")
        if not s.passed:
            all_passed = False

    return all_passed


def step_temporal() -> bool:
    """Step 4: Confirm temporal correctness tests exist and are included."""
    print("\n" + "=" * 60)
    print("STEP 4: Confirming temporal correctness tests")
    print("=" * 60)

    temporal_path = PROJECT_ROOT / "tests" / "test_temporal.py"
    exists = temporal_path.exists()

    if exists:
        # Count test functions
        content = temporal_path.read_text()
        test_count = content.count("def test_")
        print(f"  Found tests/test_temporal.py with {test_count} test(s)")
        print("  (Temporal tests run as part of Step 1)")
    else:
        print("  MISSING: tests/test_temporal.py not found")

    return exists


def step_tlc() -> bool:
    """Step 5: Run TLC model checker (conditional)."""
    print("\n" + "=" * 60)
    print("STEP 5: TLC model checker")
    print("=" * 60)

    tla_file = PROJECT_ROOT / "spec" / "biodefense.tla"
    cfg_file = PROJECT_ROOT / "spec" / "biodefense.cfg"

    if not tla_file.exists() or not cfg_file.exists():
        print("  SKIP: TLA+ specification files not found")
        return True  # Not a failure — just unavailable

    # Check for TLC (Java-based)
    tlc_cmd = shutil.which("tlc")
    java_cmd = shutil.which("java")

    if tlc_cmd:
        print(f"  Found TLC at: {tlc_cmd}")
        result = subprocess.run(
            [tlc_cmd, str(tla_file), "-config", str(cfg_file)],
            cwd=str(PROJECT_ROOT / "spec"),
            capture_output=True,
            text=True,
            timeout=300,
        )
        print(result.stdout[-500:] if len(result.stdout) > 500 else result.stdout)
        if result.returncode != 0:
            print(result.stderr[-500:] if len(result.stderr) > 500 else result.stderr)
        return result.returncode == 0
    elif java_cmd:
        # Try running TLC via tla2tools.jar if present
        tla_jar = PROJECT_ROOT / "lib" / "tla2tools.jar"
        if tla_jar.exists():
            print(f"  Running TLC via {tla_jar}")
            result = subprocess.run(
                [java_cmd, "-jar", str(tla_jar), str(tla_file),
                 "-config", str(cfg_file)],
                cwd=str(PROJECT_ROOT / "spec"),
                capture_output=True,
                text=True,
                timeout=300,
            )
            print(result.stdout[-500:] if len(result.stdout) > 500 else result.stdout)
            return result.returncode == 0

    print("  SKIP: TLC not available (install TLA+ toolbox for formal verification)")
    print("  TLA+ spec files present and ready for manual verification")
    return True  # Not a failure — conditional step


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

STEPS = {
    "tests": ("Run all tests", step_tests),
    "adversarial": ("Adversarial simulator (5 seeds)", step_adversarial),
    "traceability": ("Verify traceability links", step_traceability),
    "temporal": ("Temporal correctness tests", step_temporal),
    "tlc": ("TLC model checker", step_tlc),
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Biodefense BARE Verification Gate"
    )
    parser.add_argument(
        "--step",
        choices=list(STEPS.keys()),
        help="Run a single verification step (default: all)",
    )
    args = parser.parse_args()

    if args.step:
        name, fn = STEPS[args.step]
        print(f"\nRunning single step: {name}")
        ok = fn()
        return 0 if ok else 1

    # Run all steps
    print("\n" + "#" * 60)
    print("# BIODEFENSE BARE — VERIFICATION GATE")
    print("#" * 60)

    results = {}
    for key, (name, fn) in STEPS.items():
        try:
            results[key] = fn()
        except Exception as e:
            print(f"\n  ERROR in {name}: {e}")
            results[key] = False

    # Summary
    print("\n" + "=" * 60)
    print("VERIFICATION GATE SUMMARY")
    print("=" * 60)
    all_passed = True
    for key, (name, _) in STEPS.items():
        status = "PASS" if results.get(key, False) else "FAIL"
        print(f"  [{status}] {name}")
        if not results.get(key, False):
            all_passed = False

    if all_passed:
        print("\n  GATE RESULT: ALL CHECKS PASSED")
    else:
        print("\n  GATE RESULT: FAILED — see details above")

    print("=" * 60)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
