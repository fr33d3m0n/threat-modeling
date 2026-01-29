"""
Count Conservation Tests for STRIDE Threat Modeling v3.0

Validates the critical count conservation formula:
  P5.threat_inventory.total = P6.verified + P6.theoretical + P6.pending + P6.excluded

This ensures all threats identified in P5 are accounted for in P6 validation.

Tests include:
- CC-001: Basic count conservation validation
- CC-002: Threat reference traceability
- CC-003: Edge cases (zero threats, all excluded, etc.)
- CC-004: Schema validation
- CC-005: Cross-phase consistency
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Set

import pytest
import yaml


class CountConservationValidator:
    """
    Validates count conservation between P5 threat inventory and P6 validated risks.

    The count conservation formula ensures data integrity:
    P5.total = P6.verified + P6.theoretical + P6.pending + P6.excluded
    """

    def __init__(self, threat_inventory: Dict, validated_risks: Dict):
        self.threat_inventory = threat_inventory
        self.validated_risks = validated_risks
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate_checkpoint_1(self) -> bool:
        """
        CP1: P6.input_count = P5.threat_inventory.summary.total

        Validates that P6 acknowledges the total threat count from P5.
        """
        p5_total = self.threat_inventory.get("summary", {}).get("total", 0)
        p6_input = self.validated_risks.get("risk_summary", {}).get("total_identified", 0)

        if p5_total != p6_input:
            self.errors.append(
                f"CP1 FAIL: P5 total ({p5_total}) != P6 input count ({p6_input})"
            )
            return False
        return True

    def validate_checkpoint_2(self) -> bool:
        """
        CP2: sum(verified, theoretical, pending, excluded) = input_count

        Validates that all categorized threats equal the input count.
        """
        summary = self.validated_risks.get("risk_summary", {})

        verified = summary.get("total_verified", 0)
        theoretical = summary.get("total_theoretical", 0)
        pending = summary.get("total_pending", 0)
        excluded = summary.get("total_excluded", 0)

        categorized_total = verified + theoretical + pending + excluded
        input_count = summary.get("total_identified", 0)

        if categorized_total != input_count:
            self.errors.append(
                f"CP2 FAIL: categorized ({categorized_total}) != input ({input_count}). "
                f"Breakdown: verified={verified}, theoretical={theoretical}, "
                f"pending={pending}, excluded={excluded}"
            )
            return False
        return True

    def validate_checkpoint_3(self) -> bool:
        """
        CP3: Every threat from P5 appears in exactly one VR.threat_refs[] OR is excluded

        Validates full threat traceability.
        """
        # Collect all P5 threat IDs
        p5_threats: Set[str] = set()
        for threat in self.threat_inventory.get("threats", []):
            threat_id = threat.get("id")
            if threat_id:
                p5_threats.add(threat_id)

        # Collect all threat refs from VR entries
        covered_threats: Set[str] = set()
        for risk in self.validated_risks.get("risk_details", []):
            threat_refs = risk.get("threat_refs", [])
            covered_threats.update(threat_refs)

        # Collect excluded threats
        excluded_threats: Set[str] = set()
        for excluded in self.validated_risks.get("excluded_threats", []):
            if isinstance(excluded, dict):
                excluded_threats.add(excluded.get("threat_id", ""))
            elif isinstance(excluded, str):
                excluded_threats.add(excluded)

        # Check all P5 threats are accounted for
        all_accounted = covered_threats | excluded_threats
        missing_threats = p5_threats - all_accounted

        if missing_threats:
            self.errors.append(
                f"CP3 FAIL: {len(missing_threats)} threats not traced: {missing_threats}"
            )
            return False

        # Check for duplicate coverage
        if len(covered_threats) + len(excluded_threats) > len(all_accounted):
            self.warnings.append(
                "CP3 WARNING: Some threats appear in multiple categories"
            )

        return True

    def validate_all(self) -> Dict[str, Any]:
        """Run all validation checkpoints and return results."""
        results = {
            "cp1_input_count": self.validate_checkpoint_1(),
            "cp2_categorization": self.validate_checkpoint_2(),
            "cp3_traceability": self.validate_checkpoint_3(),
            "errors": self.errors,
            "warnings": self.warnings,
            "valid": len(self.errors) == 0,
        }

        # Calculate conservation metrics
        summary = self.validated_risks.get("risk_summary", {})
        results["metrics"] = {
            "p5_total": self.threat_inventory.get("summary", {}).get("total", 0),
            "p6_verified": summary.get("total_verified", 0),
            "p6_theoretical": summary.get("total_theoretical", 0),
            "p6_pending": summary.get("total_pending", 0),
            "p6_excluded": summary.get("total_excluded", 0),
        }

        return results


class TestCountConservationBasic:
    """CC-001: Basic count conservation validation."""

    def test_valid_conservation(self, mock_threat_inventory, mock_validated_risks):
        """Test count conservation with valid data."""
        validator = CountConservationValidator(mock_threat_inventory, mock_validated_risks)
        results = validator.validate_all()

        assert results["valid"], f"Validation failed: {results['errors']}"
        assert results["cp1_input_count"]
        assert results["cp2_categorization"]

    def test_conservation_formula(self, mock_threat_inventory, mock_validated_risks):
        """Test the count conservation formula directly."""
        p5_total = mock_threat_inventory["summary"]["total"]
        p6 = mock_validated_risks["risk_summary"]

        # Formula: P5.total = verified + theoretical + pending + excluded
        p6_sum = p6["total_verified"] + p6["total_theoretical"] + p6["total_pending"] + p6["total_excluded"]

        assert p5_total == p6_sum, f"Conservation failed: P5={p5_total}, P6 sum={p6_sum}"


class TestThreatTraceability:
    """CC-002: Threat reference traceability tests."""

    def test_all_threats_traced(self, mock_threat_inventory, mock_validated_risks):
        """Test all P5 threats appear in P6 risk references."""
        p5_threat_ids = {t["id"] for t in mock_threat_inventory["threats"]}

        # Collect refs from validated risks
        p6_threat_refs = set()
        for risk in mock_validated_risks["risk_details"]:
            p6_threat_refs.update(risk.get("threat_refs", []))

        # All P5 threats should be in P6 refs
        missing = p5_threat_ids - p6_threat_refs
        assert len(missing) == 0, f"Threats not traced: {missing}"

    def test_risk_has_threat_refs(self, mock_validated_risks):
        """Test each validated risk has at least one threat reference."""
        for risk in mock_validated_risks["risk_details"]:
            refs = risk.get("threat_refs", [])
            assert len(refs) > 0, f"Risk {risk['id']} has no threat references"

    def test_threat_id_format(self, mock_threat_inventory):
        """Test threat ID format: T-{STRIDE}-{Element}-{Seq}."""
        for threat in mock_threat_inventory["threats"]:
            threat_id = threat["id"]
            parts = threat_id.split("-")

            assert len(parts) >= 4, f"Invalid threat ID format: {threat_id}"
            assert parts[0] == "T", f"Threat ID must start with T: {threat_id}"
            assert parts[1] in ["S", "T", "R", "I", "D", "E"], f"Invalid STRIDE code: {threat_id}"


class TestEdgeCases:
    """CC-003: Edge case tests."""

    def test_zero_threats(self):
        """Test conservation with zero threats."""
        empty_inventory = {"threats": [], "summary": {"total": 0}}
        empty_risks = {
            "risk_summary": {
                "total_identified": 0,
                "total_verified": 0,
                "total_theoretical": 0,
                "total_pending": 0,
                "total_excluded": 0,
            },
            "risk_details": [],
            "excluded_threats": [],
        }

        validator = CountConservationValidator(empty_inventory, empty_risks)
        results = validator.validate_all()

        assert results["valid"]
        assert results["metrics"]["p5_total"] == 0

    def test_all_excluded(self):
        """Test conservation with all threats excluded."""
        inventory = {
            "threats": [
                {"id": "T-S-P-001-001", "stride_type": "S"},
                {"id": "T-T-DS-001-001", "stride_type": "T"},
            ],
            "summary": {"total": 2},
        }
        risks = {
            "risk_summary": {
                "total_identified": 2,
                "total_verified": 0,
                "total_theoretical": 0,
                "total_pending": 0,
                "total_excluded": 2,
            },
            "risk_details": [],
            "excluded_threats": [
                {"threat_id": "T-S-P-001-001", "reason": "False positive"},
                {"threat_id": "T-T-DS-001-001", "reason": "Out of scope"},
            ],
        }

        validator = CountConservationValidator(inventory, risks)
        results = validator.validate_all()

        assert results["valid"]
        assert results["metrics"]["p6_excluded"] == 2

    def test_all_verified(self):
        """Test conservation with all threats verified."""
        inventory = {
            "threats": [
                {"id": "T-S-P-001-001", "stride_type": "S"},
            ],
            "summary": {"total": 1},
        }
        risks = {
            "risk_summary": {
                "total_identified": 1,
                "total_verified": 1,
                "total_theoretical": 0,
                "total_pending": 0,
                "total_excluded": 0,
            },
            "risk_details": [
                {"id": "VR-001", "threat_refs": ["T-S-P-001-001"], "validation": {"status": "verified"}},
            ],
            "excluded_threats": [],
        }

        validator = CountConservationValidator(inventory, risks)
        results = validator.validate_all()

        assert results["valid"]
        assert results["metrics"]["p6_verified"] == 1

    def test_conservation_failure_detection(self):
        """Test that conservation failures are detected."""
        inventory = {
            "threats": [
                {"id": "T-S-P-001-001", "stride_type": "S"},
                {"id": "T-T-DS-001-001", "stride_type": "T"},
            ],
            "summary": {"total": 2},
        }
        # Intentionally wrong - only accounts for 1 threat
        risks = {
            "risk_summary": {
                "total_identified": 2,
                "total_verified": 1,
                "total_theoretical": 0,
                "total_pending": 0,
                "total_excluded": 0,  # Should be 1
            },
            "risk_details": [
                {"id": "VR-001", "threat_refs": ["T-S-P-001-001"]},
            ],
            "excluded_threats": [],
        }

        validator = CountConservationValidator(inventory, risks)
        results = validator.validate_all()

        assert not results["valid"], "Should detect conservation failure"
        assert len(results["errors"]) > 0


class TestSchemaValidation:
    """CC-004: Schema validation tests."""

    def test_threat_schema(self, mock_threat_inventory):
        """Test threat schema compliance."""
        required_fields = ["id", "stride_type", "element_id", "title"]

        for threat in mock_threat_inventory["threats"]:
            for field in required_fields:
                assert field in threat, f"Threat missing field: {field}"

    def test_risk_schema(self, mock_validated_risks):
        """Test validated risk schema compliance."""
        required_fields = ["id", "threat_refs", "priority"]

        for risk in mock_validated_risks["risk_details"]:
            for field in required_fields:
                assert field in risk, f"Risk missing field: {field}"

    def test_summary_schema(self, mock_validated_risks):
        """Test risk summary schema compliance."""
        required_fields = [
            "total_identified",
            "total_verified",
            "total_theoretical",
            "total_pending",
            "total_excluded",
        ]

        summary = mock_validated_risks["risk_summary"]
        for field in required_fields:
            assert field in summary, f"Summary missing field: {field}"
            assert isinstance(summary[field], int), f"Summary field {field} should be int"


class TestCrossPhaseConsistency:
    """CC-005: Cross-phase consistency tests."""

    def test_stride_distribution(self, mock_threat_inventory, mock_dfd_elements):
        """Test STRIDE distribution matches element types."""
        # Get element types from DFD
        element_types = {}
        for proc in mock_dfd_elements.get("processes", []):
            element_types[proc["id"]] = "process"
        for ds in mock_dfd_elements.get("data_stores", []):
            element_types[ds["id"]] = "datastore"
        for df in mock_dfd_elements.get("data_flows", []):
            element_types[df["id"]] = "dataflow"

        # Verify threats reference valid elements
        for threat in mock_threat_inventory["threats"]:
            element_id = threat.get("element_id")
            # Element should exist in DFD
            assert element_id in element_types or element_id.startswith("EI-"), \
                f"Threat references unknown element: {element_id}"

    def test_risk_priority_distribution(self, mock_validated_risks):
        """Test risk priorities are valid."""
        valid_priorities = ["P0", "P1", "P2", "P3"]

        for risk in mock_validated_risks["risk_details"]:
            priority = risk.get("priority")
            assert priority in valid_priorities, f"Invalid priority: {priority}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
