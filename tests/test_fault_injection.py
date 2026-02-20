"""
Tests for the fault injection framework.
"""

import pytest
from fault_injection.framework import FaultInjector, FAULT_TAXONOMY


class TestFaultTaxonomy:
    def test_taxonomy_complete(self):
        """Every fault has required fields."""
        for fault in FAULT_TAXONOMY:
            assert fault.fault_id
            assert fault.description
            assert fault.injection_method
            assert fault.expected_behavior

    def test_unique_fault_ids(self):
        ids = [f.fault_id for f in FAULT_TAXONOMY]
        assert len(ids) == len(set(ids)), "Duplicate fault IDs"


class TestFaultInjector:
    def test_out_of_bounds_signal_rejected(self):
        result = FaultInjector().inject_data_fault_out_of_bounds()
        assert result.passed

    def test_nan_signal_rejected(self):
        result = FaultInjector().inject_data_fault_nan()
        assert result.passed

    def test_no_signals_handled(self):
        result = FaultInjector().inject_data_fault_no_signals()
        assert result.passed

    def test_rapid_burst_bounded(self):
        result = FaultInjector().inject_temporal_fault_rapid_burst()
        assert result.passed

    def test_zero_confidence_handled(self):
        result = FaultInjector().inject_confidence_fault_all_zero()
        assert result.passed

    def test_double_safe_mode_idempotent(self):
        result = FaultInjector().inject_governance_fault_double_safe()
        assert result.passed

    def test_all_faults(self):
        """Run all implemented fault injections."""
        results = FaultInjector().run_all()
        for r in results:
            assert r.passed, (
                f"Fault {r.fault_id} failed: "
                f"expected: {r.expected_behavior}, "
                f"actual: {r.actual_behavior}"
            )
