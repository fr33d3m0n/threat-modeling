"""
Unit Tests for Phase Validators (P2-P7) in phase_data.py

Tests comprehensive validation logic for:
- P2: L1 coverage validation
- P3: Trust boundary validation
- P4: Security design validation
- P5: Threat inventory validation
- P6: Validated risks validation
- P7: Mitigation plan validation

Test Coverage Target: ≥80% for all validator functions
"""

import json
import os
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any
from unittest.mock import patch, MagicMock

import pytest
import yaml

# Import from conftest
from conftest import (
    mock_session_meta,
    mock_threat_inventory,
    mock_validated_risks,
    mock_dfd_elements,
    mock_trust_boundaries,
    mock_security_gaps,
    mock_mitigation_plan,
)

# Import phase_data module
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import phase_data as pd


class TestIDPatterns:
    """Test ID format regex patterns."""

    def test_trust_boundary_pattern(self):
        """Test TB-xxx pattern validation."""
        assert pd.ID_PATTERNS['trust_boundary'].match("TB-001")
        assert pd.ID_PATTERNS['trust_boundary'].match("TB-999")
        assert not pd.ID_PATTERNS['trust_boundary'].match("TB-1")
        assert not pd.ID_PATTERNS['trust_boundary'].match("TB001")
        assert not pd.ID_PATTERNS['trust_boundary'].match("tb-001")

    def test_interface_pattern(self):
        """Test IF-xxx pattern validation."""
        assert pd.ID_PATTERNS['interface'].match("IF-001")
        assert pd.ID_PATTERNS['interface'].match("IF-123")
        assert not pd.ID_PATTERNS['interface'].match("IF1")

    def test_data_node_pattern(self):
        """Test DN-xxx pattern validation."""
        assert pd.ID_PATTERNS['data_node'].match("DN-001")
        assert pd.ID_PATTERNS['data_node'].match("DN-999")
        assert not pd.ID_PATTERNS['data_node'].match("DN-1")

    def test_security_gap_pattern(self):
        """Test GAP-xxx pattern validation."""
        assert pd.ID_PATTERNS['security_gap'].match("GAP-001")
        assert pd.ID_PATTERNS['security_gap'].match("GAP-100")
        assert not pd.ID_PATTERNS['security_gap'].match("GAP-1")
        assert not pd.ID_PATTERNS['security_gap'].match("GAPS-001")

    def test_threat_pattern(self):
        """Test threat ID patterns (both formats)."""
        # New format: T-S-P-001-001
        assert pd.ID_PATTERNS['threat'].match("T-S-P-001-001")
        assert pd.ID_PATTERNS['threat'].match("T-E-DS-002-003")
        # Legacy format: T-S-P1-001
        assert pd.ID_PATTERNS['threat_alt'].match("T-S-P1-001")
        assert pd.ID_PATTERNS['threat_alt'].match("T-T-DS1-002")

    def test_mitigation_pattern(self):
        """Test MIT-xxx pattern (new format)."""
        assert pd.ID_PATTERNS['mitigation'].match("MIT-001")
        assert pd.ID_PATTERNS['mitigation'].match("MIT-999")
        assert not pd.ID_PATTERNS['mitigation'].match("M-001")  # Old format
        assert not pd.ID_PATTERNS['mitigation'].match("MIT-1")

    def test_forbidden_mitigation_pattern(self):
        """Test that M-xxx is flagged as collision with Module."""
        assert pd.ID_PATTERNS['forbidden_mitigation'].match("M-001")
        assert pd.ID_PATTERNS['forbidden_mitigation'].match("M-999")

    def test_poc_pattern(self):
        """Test POC-xxx pattern validation."""
        assert pd.ID_PATTERNS['poc'].match("POC-001")
        assert pd.ID_PATTERNS['poc'].match("POC-100")
        assert not pd.ID_PATTERNS['poc'].match("POC-1")

    def test_attack_path_pattern(self):
        """Test AP-xxx pattern validation."""
        assert pd.ID_PATTERNS['attack_path'].match("AP-001")
        assert not pd.ID_PATTERNS['attack_path'].match("AP-1")

    def test_attack_chain_pattern(self):
        """Test AC-xxx pattern validation."""
        assert pd.ID_PATTERNS['attack_chain'].match("AC-001")
        assert not pd.ID_PATTERNS['attack_chain'].match("AC1")


class TestSecurityDomains:
    """Test security domain configuration."""

    def test_domain_count(self):
        """Verify 16 security domains are defined."""
        assert len(pd.SECURITY_DOMAINS) == 16

    def test_required_domains(self):
        """Verify all required domains are present."""
        required = [
            "AUTHN", "AUTHZ", "INPUT", "OUTPUT", "CRYPTO", "LOGGING",
            "ERROR", "API", "DATA", "CONFIG", "INFRA", "SUPPLY",
            "AI", "MOBILE", "CLOUD", "AGENTIC"
        ]
        for domain in required:
            assert domain in pd.SECURITY_DOMAINS, f"Missing domain: {domain}"


def create_phase_data_file(temp_dir: str, phase: int, data: Dict) -> Path:
    """Helper to create phase data file in correct location."""
    # Use legacy path format that load_phase_data expects
    data_dir = Path(temp_dir) / "Risk_Assessment_Report" / ".phase_working" / "phase_data"
    data_dir.mkdir(parents=True, exist_ok=True)

    phase_file = data_dir / f"phase{phase}.yaml"
    with open(phase_file, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

    return phase_file


class TestP3TrustBoundaryValidation:
    """Test P3 trust boundary validation."""

    @pytest.fixture
    def temp_project(self, mock_trust_boundaries: Dict):
        """Create temporary project with P3 data."""
        temp_dir = tempfile.mkdtemp()

        # Write P3 phase data in correct YAML format
        p3_data = {
            "phase": 3,
            "extracted_at": "2026-01-30T12:00:00Z",
            "blocks": {
                "trust_boundaries": mock_trust_boundaries,
            }
        }
        create_phase_data_file(temp_dir, 3, p3_data)

        yield temp_dir
        shutil.rmtree(temp_dir)

    def test_valid_trust_boundaries(self, temp_project: str, mock_trust_boundaries: Dict):
        """Test validation with valid trust boundaries."""
        result = pd.validate_p3_trust_boundaries(temp_project)

        assert result["status"] == "passed"
        assert result["passed"] is True
        assert result["boundary_count"] == 3
        assert "TB-001" in result["boundary_ids"]

    def test_missing_trust_boundaries_block(self):
        """Test validation when trust_boundaries block is missing."""
        temp_dir = tempfile.mkdtemp()
        try:
            p3_data = {"phase": 3, "blocks": {}}
            create_phase_data_file(temp_dir, 3, p3_data)

            result = pd.validate_p3_trust_boundaries(temp_dir)
            assert result["status"] == "blocking"
            assert "Missing trust_boundaries block" in result["message"]
        finally:
            shutil.rmtree(temp_dir)

    def test_invalid_boundary_id_format(self):
        """Test validation with invalid boundary ID format."""
        temp_dir = tempfile.mkdtemp()
        try:
            p3_data = {
                "phase": 3,
                "blocks": {
                    "trust_boundaries": {
                        "boundaries": [
                            {"id": "BOUNDARY-1", "type": "Network"},  # Invalid ID
                        ]
                    }
                }
            }
            create_phase_data_file(temp_dir, 3, p3_data)

            result = pd.validate_p3_trust_boundaries(temp_dir)
            assert result["status"] == "blocking"
            assert len(result["blocking_issues"]) > 0
            assert any("invalid_id" in str(i) for i in result["blocking_issues"])
        finally:
            shutil.rmtree(temp_dir)

    def test_invalid_boundary_type(self):
        """Test validation with invalid boundary type."""
        temp_dir = tempfile.mkdtemp()
        try:
            p3_data = {
                "phase": 3,
                "blocks": {
                    "trust_boundaries": {
                        "boundaries": [
                            {"id": "TB-001", "type": "Invalid"},  # Invalid type
                        ]
                    }
                }
            }
            create_phase_data_file(temp_dir, 3, p3_data)

            result = pd.validate_p3_trust_boundaries(temp_dir)
            assert result["status"] == "blocking"
            assert any("invalid_type" in str(i) for i in result["blocking_issues"])
        finally:
            shutil.rmtree(temp_dir)


class TestP4SecurityDesignValidation:
    """Test P4 security design validation."""

    @pytest.fixture
    def temp_project(self, mock_security_gaps: Dict):
        """Create temporary project with P4 data."""
        temp_dir = tempfile.mkdtemp()

        p4_data = {
            "phase": 4,
            "extracted_at": "2026-01-30T12:00:00Z",
            "blocks": {
                "security_gaps": mock_security_gaps,
                "design_matrix": mock_security_gaps.get("design_matrix", {}),
            }
        }
        create_phase_data_file(temp_dir, 4, p4_data)

        yield temp_dir
        shutil.rmtree(temp_dir)

    def test_valid_security_gaps(self, temp_project: str, mock_security_gaps: Dict):
        """Test validation with valid security gaps."""
        result = pd.validate_p4_security_design(temp_project)

        assert result["status"] == "passed"
        assert result["passed"] is True
        assert result["gap_count"] == 4
        assert "GAP-001" in result["gap_ids"]

    def test_invalid_gap_id_format(self):
        """Test validation with invalid gap ID format."""
        temp_dir = tempfile.mkdtemp()
        try:
            p4_data = {
                "phase": 4,
                "blocks": {
                    "security_gaps": {
                        "gaps": [
                            {"id": "G-1", "domain": "AUTHN", "severity": "HIGH"},  # Invalid ID
                        ]
                    }
                }
            }
            create_phase_data_file(temp_dir, 4, p4_data)

            result = pd.validate_p4_security_design(temp_dir)
            assert result["status"] == "blocking"
            assert any("invalid_gap_id" in str(i) for i in result["blocking_issues"])
        finally:
            shutil.rmtree(temp_dir)

    def test_invalid_security_domain(self):
        """Test validation with invalid security domain."""
        temp_dir = tempfile.mkdtemp()
        try:
            p4_data = {
                "phase": 4,
                "blocks": {
                    "security_gaps": {
                        "gaps": [
                            {"id": "GAP-001", "domain": "INVALID_DOMAIN", "severity": "HIGH"},
                        ]
                    }
                }
            }
            create_phase_data_file(temp_dir, 4, p4_data)

            result = pd.validate_p4_security_design(temp_dir)
            assert result["status"] == "blocking"
            assert any("invalid_domain" in str(i) for i in result["blocking_issues"])
        finally:
            shutil.rmtree(temp_dir)


class TestP5ThreatInventoryValidation:
    """Test P5 threat inventory validation."""

    @pytest.fixture
    def temp_project(self, mock_threat_inventory: Dict):
        """Create temporary project with P5 data."""
        temp_dir = tempfile.mkdtemp()

        p5_data = {
            "phase": 5,
            "extracted_at": "2026-01-30T12:00:00Z",
            "blocks": {
                "threat_inventory": mock_threat_inventory,
            }
        }
        create_phase_data_file(temp_dir, 5, p5_data)

        yield temp_dir
        shutil.rmtree(temp_dir)

    def test_valid_threat_inventory(self, temp_project: str, mock_threat_inventory: Dict):
        """Test validation with valid threat inventory."""
        result = pd.validate_p5_threat_inventory(temp_project)

        assert result["status"] == "passed"
        assert result["passed"] is True
        assert result["threat_count"] == 5
        assert result["stride_distribution"]["S"] == 1

    def test_count_mismatch_detection(self):
        """Test detection of count mismatch in summary."""
        temp_dir = tempfile.mkdtemp()
        try:
            p5_data = {
                "phase": 5,
                "blocks": {
                    "threat_inventory": {
                        "threats": [
                            {"id": "T-S-P-001-001", "stride_type": "S"},
                            {"id": "T-T-DS-001-001", "stride_type": "T"},
                        ],
                        "summary": {
                            "total": 5,  # Mismatch! Actual is 2
                            "by_stride": {"S": 1, "T": 1},
                        }
                    }
                }
            }
            create_phase_data_file(temp_dir, 5, p5_data)

            result = pd.validate_p5_threat_inventory(temp_dir)
            assert result["status"] == "blocking"
            assert any("count_mismatch" in str(i) for i in result["blocking_issues"])
        finally:
            shutil.rmtree(temp_dir)

    def test_invalid_threat_id_format(self):
        """Test validation with invalid threat ID format."""
        temp_dir = tempfile.mkdtemp()
        try:
            p5_data = {
                "phase": 5,
                "blocks": {
                    "threat_inventory": {
                        "threats": [
                            {"id": "THREAT-001", "stride_type": "S"},  # Invalid format
                        ],
                        "summary": {"total": 1, "by_stride": {"S": 1}},
                    }
                }
            }
            create_phase_data_file(temp_dir, 5, p5_data)

            result = pd.validate_p5_threat_inventory(temp_dir)
            assert result["status"] == "blocking"
            assert any("invalid_threat_id" in str(i) for i in result["blocking_issues"])
        finally:
            shutil.rmtree(temp_dir)


class TestP6ValidatedRisksValidation:
    """Test P6 validated risks validation."""

    @pytest.fixture
    def temp_project(self, mock_validated_risks: Dict):
        """Create temporary project with P6 data."""
        temp_dir = tempfile.mkdtemp()

        p6_data = {
            "phase": 6,
            "extracted_at": "2026-01-30T12:00:00Z",
            "blocks": {
                "validated_risks": mock_validated_risks,
            }
        }
        create_phase_data_file(temp_dir, 6, p6_data)

        yield temp_dir
        shutil.rmtree(temp_dir)

    def test_valid_validated_risks(self, temp_project: str, mock_validated_risks: Dict):
        """Test validation with valid validated risks."""
        result = pd.validate_p6_validated_risks(temp_project)

        assert result["status"] == "passed"
        assert result["passed"] is True
        assert result["risk_count"] == 4
        assert "VR-001" in result["vr_ids"]

    def test_missing_threat_refs(self):
        """Test validation when VR is missing threat_refs."""
        temp_dir = tempfile.mkdtemp()
        try:
            p6_data = {
                "phase": 6,
                "blocks": {
                    "validated_risks": {
                        "risk_summary": {"total_identified": 1},
                        "risk_details": [
                            {"id": "VR-001", "title": "Test Risk"},  # Missing threat_refs
                        ],
                    }
                }
            }
            create_phase_data_file(temp_dir, 6, p6_data)

            result = pd.validate_p6_validated_risks(temp_dir)
            assert result["status"] == "blocking"
            assert any("missing_threat_refs" in str(i) for i in result["blocking_issues"])
        finally:
            shutil.rmtree(temp_dir)

    def test_invalid_vr_id_format(self):
        """Test validation with invalid VR ID format."""
        temp_dir = tempfile.mkdtemp()
        try:
            p6_data = {
                "phase": 6,
                "blocks": {
                    "validated_risks": {
                        "risk_summary": {"total_identified": 1},
                        "risk_details": [
                            {"id": "RISK-001", "threat_refs": ["T-S-P-001-001"]},  # Invalid format
                        ],
                    }
                }
            }
            create_phase_data_file(temp_dir, 6, p6_data)

            result = pd.validate_p6_validated_risks(temp_dir)
            assert result["status"] == "blocking"
            assert any("invalid_vr_id" in str(i) for i in result["blocking_issues"])
        finally:
            shutil.rmtree(temp_dir)


class TestP7MitigationPlanValidation:
    """Test P7 mitigation plan validation."""

    @pytest.fixture
    def temp_project(self, mock_mitigation_plan: Dict):
        """Create temporary project with P7 data."""
        temp_dir = tempfile.mkdtemp()

        p7_data = {
            "phase": 7,
            "extracted_at": "2026-01-30T12:00:00Z",
            "blocks": {
                "mitigation_plan": mock_mitigation_plan,
                "roadmap": mock_mitigation_plan.get("roadmap", {}),
            }
        }
        create_phase_data_file(temp_dir, 7, p7_data)

        yield temp_dir
        shutil.rmtree(temp_dir)

    def test_valid_mitigation_plan(self, temp_project: str, mock_mitigation_plan: Dict):
        """Test validation with valid mitigation plan."""
        result = pd.validate_p7_mitigation_plan(temp_project)

        assert result["status"] == "passed"
        assert result["passed"] is True
        assert result["mitigation_count"] == 3
        assert "MIT-001" in result["mit_ids"]

    def test_invalid_mit_id_format(self):
        """Test validation with invalid MIT ID format."""
        temp_dir = tempfile.mkdtemp()
        try:
            p7_data = {
                "phase": 7,
                "blocks": {
                    "mitigation_plan": {
                        "mitigations": [
                            {"id": "MITIGATION-1", "risk_refs": ["VR-001"]},  # Invalid format
                        ]
                    }
                }
            }
            create_phase_data_file(temp_dir, 7, p7_data)

            result = pd.validate_p7_mitigation_plan(temp_dir)
            assert result["status"] == "blocking"
            assert any("invalid_mit_id" in str(i) for i in result["blocking_issues"])
        finally:
            shutil.rmtree(temp_dir)

    def test_forbidden_m_xxx_format(self):
        """Test that old M-xxx format triggers error."""
        temp_dir = tempfile.mkdtemp()
        try:
            p7_data = {
                "phase": 7,
                "blocks": {
                    "mitigation_plan": {
                        "mitigations": [
                            {"id": "M-001", "risk_refs": ["VR-001"]},  # Forbidden format
                        ]
                    }
                }
            }
            create_phase_data_file(temp_dir, 7, p7_data)

            result = pd.validate_p7_mitigation_plan(temp_dir)
            assert result["status"] == "blocking"
            assert any("forbidden_mit_format" in str(i) for i in result["blocking_issues"])
        finally:
            shutil.rmtree(temp_dir)

    def test_missing_risk_refs(self):
        """Test validation when mitigation is missing risk_refs."""
        temp_dir = tempfile.mkdtemp()
        try:
            p7_data = {
                "phase": 7,
                "blocks": {
                    "mitigation_plan": {
                        "mitigations": [
                            {"id": "MIT-001", "title": "Test Mitigation"},  # Missing risk_refs
                        ]
                    }
                }
            }
            create_phase_data_file(temp_dir, 7, p7_data)

            result = pd.validate_p7_mitigation_plan(temp_dir)
            assert result["status"] == "blocking"
            assert any("missing_risk_refs" in str(i) for i in result["blocking_issues"])
        finally:
            shutil.rmtree(temp_dir)


class TestValidatePhaseRouter:
    """Test the validate_phase routing function."""

    def test_routes_to_p3_validator(self):
        """Test that phase 3 routes to trust boundary validator."""
        # With no data, should return error
        result = pd.validate_phase(3, "/nonexistent")
        assert result["phase"] == 3
        assert result["status"] == "error"

    def test_routes_to_p4_validator(self):
        """Test that phase 4 routes to security design validator."""
        result = pd.validate_phase(4, "/nonexistent")
        assert result["phase"] == 4
        assert result["status"] == "error"

    def test_routes_to_p5_validator(self):
        """Test that phase 5 routes to threat inventory validator."""
        result = pd.validate_phase(5, "/nonexistent")
        assert result["phase"] == 5
        assert result["status"] == "error"

    def test_routes_to_p6_validator(self):
        """Test that phase 6 routes to validated risks validator."""
        result = pd.validate_phase(6, "/nonexistent")
        assert result["phase"] == 6
        assert result["status"] == "error"

    def test_routes_to_p7_validator(self):
        """Test that phase 7 routes to mitigation plan validator."""
        result = pd.validate_phase(7, "/nonexistent")
        assert result["phase"] == 7
        assert result["status"] == "error"

    def test_routes_to_p8_validator(self):
        """Test that phase 8 routes to report validator."""
        result = pd.validate_phase(8, "/nonexistent")
        assert result["phase"] == 8
        assert "report" in result.get("gate", result.get("message", "")).lower()

    def test_unknown_phase_returns_error(self):
        """Test that unknown phase returns error."""
        result = pd.validate_phase(99, "/nonexistent")
        assert result["status"] == "error"
        assert "Unknown phase" in result["message"]


class TestRequiredBlocksConfiguration:
    """Test that REQUIRED_BLOCKS configuration is correct."""

    def test_all_phases_have_required_blocks(self):
        """Verify required blocks are defined for key phases."""
        assert 1 in pd.REQUIRED_BLOCKS
        assert 2 in pd.REQUIRED_BLOCKS
        assert 3 in pd.REQUIRED_BLOCKS
        assert 4 in pd.REQUIRED_BLOCKS
        assert 5 in pd.REQUIRED_BLOCKS
        assert 6 in pd.REQUIRED_BLOCKS
        assert 7 in pd.REQUIRED_BLOCKS

    def test_p3_requires_trust_boundaries(self):
        """P3 should require trust_boundaries block."""
        assert "trust_boundaries" in pd.REQUIRED_BLOCKS[3]

    def test_p4_requires_security_gaps(self):
        """P4 should require security_gaps block."""
        assert "security_gaps" in pd.REQUIRED_BLOCKS[4]

    def test_p5_requires_threat_inventory(self):
        """P5 should require threat_inventory block."""
        assert "threat_inventory" in pd.REQUIRED_BLOCKS[5]

    def test_p6_requires_validated_risks(self):
        """P6 should require validated_risks block."""
        assert "validated_risks" in pd.REQUIRED_BLOCKS[6]

    def test_p7_requires_mitigation_plan(self):
        """P7 should require mitigation_plan block."""
        assert "mitigation_plan" in pd.REQUIRED_BLOCKS[7]


class TestPhaseBlocksConfiguration:
    """Test that PHASE_BLOCKS configuration includes all expected blocks."""

    def test_p3_blocks(self):
        """P3 should define trust boundary related blocks."""
        p3_blocks = pd.PHASE_BLOCKS[3]
        assert "trust_boundaries" in p3_blocks
        assert "interfaces" in p3_blocks
        assert "data_nodes" in p3_blocks

    def test_p4_blocks(self):
        """P4 should define security design blocks."""
        p4_blocks = pd.PHASE_BLOCKS[4]
        assert "security_gaps" in p4_blocks
        assert "design_matrix" in p4_blocks

    def test_p6_blocks(self):
        """P6 should define risk validation blocks."""
        p6_blocks = pd.PHASE_BLOCKS[6]
        assert "validated_risks" in p6_blocks
        assert "attack_paths" in p6_blocks
        assert "attack_chains" in p6_blocks
        assert "poc_details" in p6_blocks

    def test_p7_blocks(self):
        """P7 should define mitigation blocks."""
        p7_blocks = pd.PHASE_BLOCKS[7]
        assert "mitigation_plan" in p7_blocks
        assert "roadmap" in p7_blocks
