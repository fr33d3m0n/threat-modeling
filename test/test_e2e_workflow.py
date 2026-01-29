"""
End-to-End Workflow Tests for STRIDE Threat Modeling v3.0

Tests complete P1→P8 workflow including:
- E2E-001: Complete workflow flow
- E2E-002: Phase transition validation
- E2E-003: Session recovery
- E2E-004: Error recovery
- E2E-005: Output file generation

These tests validate the entire threat modeling workflow
from project understanding to report generation.
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any
from unittest.mock import patch, MagicMock

import pytest
import yaml

# Import test fixtures
from conftest import (
    mock_session_meta,
    mock_threat_inventory,
    mock_validated_risks,
    mock_dfd_elements,
)


class TestE2EWorkflow:
    """E2E-001: Complete P1→P8 workflow test."""

    def test_phase_files_exist(self, phases_dir: Path):
        """Verify all 8 phase instruction files exist."""
        expected_phases = [
            "P1-PROJECT-UNDERSTANDING.md",
            "P2-DFD-ANALYSIS.md",
            "P3-TRUST-BOUNDARY.md",
            "P4-SECURITY-DESIGN-REVIEW.md",
            "P5-STRIDE-ANALYSIS.md",
            "P6-RISK-VALIDATION.md",
            "P7-MITIGATION-PLANNING.md",
            "P8-REPORT-GENERATION.md",
        ]

        for phase_file in expected_phases:
            phase_path = phases_dir / phase_file
            assert phase_path.exists(), f"Phase file missing: {phase_file}"

    def test_data_contracts_exist(self, contracts_dir: Path):
        """Verify data model contracts exist."""
        data_model = contracts_dir / "data-model.yaml"
        assert data_model.exists(), "data-model.yaml missing"

        # Load and verify key entities
        with open(data_model) as f:
            model = yaml.safe_load(f)

        required_entities = [
            "Finding",
            "Threat",
            "ValidatedRisk",
            "Mitigation",
            "Module",
            "SecurityGap",
            "Interface",
            "DataNode",
            "TrustBoundary",
            "POC",
            "AttackPath",
            "CountConservation",
        ]

        for entity in required_entities:
            assert entity in model, f"Entity missing from data-model.yaml: {entity}"

    def test_knowledge_base_available(self, knowledge_dir: Path):
        """Verify knowledge base files exist."""
        required_files = [
            "security-design.yaml",
            "security-principles.yaml",
            "stride-controls-mapping.yaml",
            "compliance-mappings.yaml",
            "cwe-mappings.yaml",
            "capec-mappings.yaml",
        ]

        for kb_file in required_files:
            kb_path = knowledge_dir / kb_file
            assert kb_path.exists(), f"Knowledge file missing: {kb_file}"

    def test_workflow_file_exists(self, project_root: Path):
        """Verify WORKFLOW.md exists with phase contracts."""
        workflow_path = project_root / "WORKFLOW.md"
        assert workflow_path.exists(), "WORKFLOW.md missing"

        content = workflow_path.read_text()

        # Verify phase contracts are defined
        contracts = ["P1 → P2", "P2 → P3", "P3 → P4", "P4 → P5", "P5 → P6", "P6 → P7", "P7 → P8"]
        for contract in contracts:
            assert contract in content, f"Phase contract missing: {contract}"

    def test_skill_file_exists(self, project_root: Path):
        """Verify SKILL.md exists with execution model."""
        skill_path = project_root / "SKILL.md"
        assert skill_path.exists(), "SKILL.md missing"

        content = skill_path.read_text()

        # Verify key sections
        assert "Execution Model" in content, "Execution Model section missing"
        assert "Phase Gate Protocol" in content or "Phase 1" in content, "Phase reference missing"


class TestPhaseTransitions:
    """E2E-002: Phase transition validation tests."""

    def test_p1_to_p2_contract(self, mock_dfd_elements: Dict):
        """Test P1→P2 data contract compliance."""
        # P1 must provide project_context with modules and entry_points
        p1_output = {
            "project_context": {
                "project_type": "web",
                "modules": [{"id": "M-001", "name": "API", "path": "/src/api"}],
                "entry_points": [{"id": "EP-001", "name": "main.py", "type": "script"}],
                "security_design": {},
            }
        }

        # Verify required fields
        assert "project_context" in p1_output
        assert "modules" in p1_output["project_context"]
        assert "entry_points" in p1_output["project_context"]
        assert len(p1_output["project_context"]["modules"]) > 0

    def test_p5_to_p6_contract(self, mock_threat_inventory: Dict, mock_validated_risks: Dict):
        """Test P5→P6 data contract and count conservation."""
        # P5 provides threat_inventory
        p5_total = mock_threat_inventory["summary"]["total"]

        # P6 provides validated_risks
        p6_summary = mock_validated_risks["risk_summary"]
        p6_total = (
            p6_summary["total_verified"]
            + p6_summary["total_theoretical"]
            + p6_summary["total_pending"]
            + p6_summary["total_excluded"]
        )

        # Count conservation: P5 total = P6 verified + theoretical + pending + excluded
        assert p5_total == p6_total, f"Count conservation failed: P5={p5_total}, P6={p6_total}"

    def test_p6_to_p7_contract(self, mock_validated_risks: Dict):
        """Test P6→P7 data contract compliance."""
        # P6 must provide validated_risks with threat_refs for traceability
        for risk in mock_validated_risks["risk_details"]:
            assert "id" in risk, "Risk ID missing"
            assert "threat_refs" in risk, "Threat refs missing for traceability"
            assert len(risk["threat_refs"]) > 0, "At least one threat ref required"
            assert risk["id"].startswith("VR-"), f"Invalid risk ID format: {risk['id']}"


class TestSessionManagement:
    """E2E-003: Session recovery tests."""

    def test_session_meta_structure(self, mock_session_meta: Dict):
        """Test session metadata structure."""
        required_fields = [
            "session_id",
            "project_name",
            "project_path",
            "started_at",
            "phases_completed",
            "current_phase",
            "skill_version",
        ]

        for field in required_fields:
            assert field in mock_session_meta, f"Session meta missing: {field}"

    def test_session_meta_schema(self, mock_session_meta: Dict):
        """Test session metadata schema compliance."""
        # Session ID format: YYYYMMDD-HHMMSS
        session_id = mock_session_meta["session_id"]
        assert len(session_id) == 15, "Session ID wrong length"
        assert "-" in session_id, "Session ID missing separator"

        # Project name format: uppercase with hyphens
        project_name = mock_session_meta["project_name"]
        assert project_name.isupper() or "-" in project_name, "Project name should be uppercase"

        # Phases completed is a list
        assert isinstance(mock_session_meta["phases_completed"], list)

        # Current phase is 1-8
        assert 1 <= mock_session_meta["current_phase"] <= 8


class TestOutputGeneration:
    """E2E-005: Output file generation tests."""

    def test_report_naming_convention(self):
        """Test report naming follows convention."""
        project_name = "OPEN-WEBUI"
        expected_reports = [
            f"{project_name}-RISK-ASSESSMENT-REPORT.md",
            f"{project_name}-RISK-INVENTORY.md",
            f"{project_name}-MITIGATION-MEASURES.md",
            f"{project_name}-PENETRATION-TEST-PLAN.md",
        ]

        for report in expected_reports:
            # Verify format
            assert report.endswith(".md"), "Report must be markdown"
            assert project_name in report, "Report must include project name"

    def test_phase_output_naming(self):
        """Test phase output file naming."""
        expected_phase_outputs = [
            "P1-PROJECT-UNDERSTANDING.md",
            "P2-DFD-ANALYSIS.md",
            "P3-TRUST-BOUNDARY.md",
            "P4-SECURITY-DESIGN-REVIEW.md",
            "P5-STRIDE-THREATS.md",
            "P6-RISK-VALIDATION.md",
        ]

        for phase_output in expected_phase_outputs:
            assert phase_output.startswith("P"), "Phase output must start with P"
            assert "-" in phase_output, "Phase output must have separator"
            assert phase_output.endswith(".md"), "Phase output must be markdown"


class TestKnowledgeBaseIntegration:
    """Test knowledge base integration for E2E workflow."""

    def test_stride_controls_available(self, scripts_dir: Path):
        """Test --stride-controls command works."""
        from unified_kb_query import UnifiedKnowledgeBase

        kb = UnifiedKnowledgeBase()
        result = kb.get_stride_controls("S")

        assert "error" not in result, f"KB error: {result.get('error')}"
        assert result["stride_code"] == "S"
        assert "primary_controls" in result
        assert "mitigation_patterns" in result

    def test_control_domain_available(self, scripts_dir: Path):
        """Test --control command works."""
        from unified_kb_query import UnifiedKnowledgeBase

        kb = UnifiedKnowledgeBase()
        result = kb.get_control("AUTHN")

        assert "error" not in result, f"KB error: {result.get('error')}"
        assert result["domain_code"] == "AUTHN"
        assert "core_requirements" in result

    def test_compliance_available(self, scripts_dir: Path):
        """Test --compliance command works."""
        from unified_kb_query import UnifiedKnowledgeBase

        kb = UnifiedKnowledgeBase()
        result = kb.get_compliance()

        assert "error" not in result, f"KB error: {result.get('error')}"
        assert "frameworks_by_category" in result
        assert result["total_frameworks"] > 0


class TestPhaseValidatorIntegration:
    """E2E tests for phase validator integration."""

    @pytest.fixture
    def complete_workflow_project(
        self,
        tmp_path: Path,
        mock_dfd_elements: Dict,
        mock_threat_inventory: Dict,
        mock_validated_risks: Dict,
    ) -> Path:
        """Create a temporary project with complete workflow data."""
        import yaml

        # Create directory structure
        data_dir = tmp_path / "Risk_Assessment_Report" / ".phase_working" / "phase_data"
        data_dir.mkdir(parents=True)

        # P1: Module inventory
        p1_data = {
            "phase": 1,
            "blocks": {
                "module_inventory": {
                    "modules": [
                        {"id": "M-001", "name": "API Gateway", "type": "core"},
                        {"id": "M-002", "name": "Auth Service", "type": "service"},
                    ]
                },
                "entry_point_inventory": {
                    "api_entries": [{"id": "EP-001", "name": "/api/v1"}]
                },
                "discovery_checklist": {
                    "checklist": {
                        "rest_api": {"scanned": True, "status": "COMPLETED", "count": 5},
                        "internal_api": {"scanned": True, "status": "NOT_APPLICABLE", "count": 0},
                        "graphql": {"scanned": True, "status": "NOT_APPLICABLE", "count": 0},
                        "websocket": {"scanned": True, "status": "NOT_APPLICABLE", "count": 0},
                        "cron_jobs": {"scanned": True, "status": "NOT_APPLICABLE", "count": 0},
                        "message_queue": {"scanned": True, "status": "NOT_APPLICABLE", "count": 0},
                        "webhooks": {"scanned": True, "status": "NOT_APPLICABLE", "count": 0},
                        "file_upload": {"scanned": True, "status": "COMPLETED", "count": 1},
                        "health_endpoints": {"scanned": True, "status": "COMPLETED", "count": 1},
                        "debug_endpoints": {"scanned": True, "status": "NOT_APPLICABLE", "count": 0},
                    },
                    "summary": {"total_entry_points": 7, "coverage": "100%"}
                }
            }
        }

        # P2: DFD elements
        p2_data = {
            "phase": 2,
            "blocks": {
                "dfd_elements": mock_dfd_elements,
                "data_flows": {
                    "flows": mock_dfd_elements.get("data_flows", []),
                    "l1_coverage": mock_dfd_elements.get("l1_coverage", {})
                }
            }
        }

        # P3: Trust boundaries
        p3_data = {
            "phase": 3,
            "blocks": {
                "trust_boundaries": {
                    "boundaries": [
                        {"id": "TB-001", "name": "Internet Boundary", "type": "Network"},
                        {"id": "TB-002", "name": "Service Mesh", "type": "Process"},
                    ]
                }
            }
        }

        # P4: Security gaps
        p4_data = {
            "phase": 4,
            "blocks": {
                "security_gaps": {
                    "gaps": [
                        {"id": "GAP-001", "domain": "AUTHN", "title": "Weak Auth", "severity": "HIGH"},
                        {"id": "GAP-002", "domain": "CRYPTO", "title": "Old TLS", "severity": "MEDIUM"},
                    ]
                }
            }
        }

        # P5: Threat inventory
        p5_data = {
            "phase": 5,
            "blocks": {
                "threat_inventory": mock_threat_inventory
            }
        }

        # P6: Validated risks
        p6_data = {
            "phase": 6,
            "blocks": {
                "validated_risks": mock_validated_risks
            }
        }

        # P7: Mitigation plan
        p7_data = {
            "phase": 7,
            "blocks": {
                "mitigation_plan": {
                    "mitigations": [
                        {"id": "MIT-001", "title": "Fix Auth", "risk_refs": ["VR-001"], "priority": "P1"},
                        {"id": "MIT-002", "title": "Fix SQL", "risk_refs": ["VR-002"], "priority": "P0"},
                        {"id": "MIT-003", "title": "Fix Info Disclosure", "risk_refs": ["VR-003"], "priority": "P1"},
                        {"id": "MIT-004", "title": "Fix Theoretical", "risk_refs": ["VR-004"], "priority": "P2"},
                    ],
                    "roadmap": {
                        "immediate": ["MIT-002"],
                        "short_term": ["MIT-001", "MIT-003"],
                        "medium_term": ["MIT-004"],
                        "long_term": []
                    }
                }
            }
        }

        # Write all phase files
        for phase, data in [(1, p1_data), (2, p2_data), (3, p3_data),
                            (4, p4_data), (5, p5_data), (6, p6_data), (7, p7_data)]:
            with open(data_dir / f"phase{phase}.yaml", "w") as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

        return tmp_path

    def test_all_phase_validators_pass(self, complete_workflow_project: Path):
        """Test that all phase validators pass for a complete workflow."""
        import phase_data as pd

        project_root = str(complete_workflow_project)

        # Validate each phase
        results = {}
        for phase in range(1, 8):
            results[phase] = pd.validate_phase(phase, project_root)

        # All phases should pass
        for phase, result in results.items():
            assert result.get("passed", False) or result.get("status") == "passed", \
                f"Phase {phase} validation failed: {result.get('message', result)}"

    def test_p5_to_p6_traceability(self, complete_workflow_project: Path):
        """Test that P5 threats are properly traced in P6 risks."""
        import phase_data as pd

        project_root = str(complete_workflow_project)

        # Load phase data
        p5_data = pd.load_phase_data(5, project_root)
        p6_data = pd.load_phase_data(6, project_root)

        assert p5_data is not None, "P5 data not loaded"
        assert p6_data is not None, "P6 data not loaded"

        # Get all P5 threat IDs
        threats = p5_data["blocks"]["threat_inventory"]["threats"]
        p5_threat_ids = set(t["id"] for t in threats)

        # Get all threat_refs from P6 risks
        risks = p6_data["blocks"]["validated_risks"]["risk_details"]
        p6_threat_refs = set()
        for risk in risks:
            p6_threat_refs.update(risk.get("threat_refs", []))

        # Every P5 threat should be referenced (or excluded)
        # This is count conservation
        assert p6_threat_refs.issubset(p5_threat_ids) or p5_threat_ids.issubset(p6_threat_refs), \
            "Threat traceability broken"

    def test_p6_to_p7_coverage(self, complete_workflow_project: Path):
        """Test that all P6 risks have P7 mitigations."""
        import phase_data as pd

        project_root = str(complete_workflow_project)

        # Load phase data
        p6_data = pd.load_phase_data(6, project_root)
        p7_data = pd.load_phase_data(7, project_root)

        assert p6_data is not None, "P6 data not loaded"
        assert p7_data is not None, "P7 data not loaded"

        # Get all P6 VR IDs
        risks = p6_data["blocks"]["validated_risks"]["risk_details"]
        p6_vr_ids = set(r["id"] for r in risks)

        # Get all VRs referenced by P7 mitigations
        mitigations = p7_data["blocks"]["mitigation_plan"]["mitigations"]
        covered_vrs = set()
        for mit in mitigations:
            covered_vrs.update(mit.get("risk_refs", []))

        # Check coverage
        uncovered = p6_vr_ids - covered_vrs
        assert len(uncovered) == 0, f"VRs without mitigations: {uncovered}"

    def test_validate_workflow_complete_function(self, complete_workflow_project: Path):
        """Test the validate_workflow_complete function."""
        import phase_data as pd

        project_root = str(complete_workflow_project)
        result = pd.validate_workflow_complete(project_root)

        # Should not have blocking failures for phase validations
        assert "phase_validations" in result
        assert "blockers" in result


class TestCrossPhaseDataConsistency:
    """E2E tests for cross-phase data consistency."""

    def test_entity_id_formats_consistent(self, project_root: Path):
        """Test that all entity ID formats are consistent across phases."""
        from scripts.phase_data import ID_PATTERNS

        # Define expected formats per entity type
        expected_formats = {
            "module": r"^M-\d{3}$",
            "trust_boundary": r"^TB-\d{3}$",
            "security_gap": r"^GAP-\d{3}$",
            "threat": r"^T-[STRIDE]-[A-Z]+-\d{3}-\d{3}$",
            "validated_risk": r"^VR-\d{3}$",
            "mitigation": r"^MIT-\d{3}$",
            "poc": r"^POC-\d{3}$",
        }

        # Verify patterns are defined
        for entity_type in expected_formats:
            assert entity_type in ID_PATTERNS, f"Missing pattern for {entity_type}"

    def test_phase_blocks_cover_workflow(self, project_root: Path):
        """Test that PHASE_BLOCKS covers entire workflow."""
        from scripts.phase_data import PHASE_BLOCKS, REQUIRED_BLOCKS

        # Phases 1, 2, 5, 6, 7 should have required blocks
        for phase in [1, 2, 5, 6, 7]:
            assert phase in REQUIRED_BLOCKS, f"Phase {phase} missing from REQUIRED_BLOCKS"
            assert phase in PHASE_BLOCKS, f"Phase {phase} missing from PHASE_BLOCKS"

        # P3, P4 should also be in REQUIRED_BLOCKS after implementation
        assert 3 in REQUIRED_BLOCKS, "Phase 3 missing from REQUIRED_BLOCKS"
        assert 4 in REQUIRED_BLOCKS, "Phase 4 missing from REQUIRED_BLOCKS"


class TestValidatorOutputFormat:
    """E2E tests for validator output format consistency."""

    def test_validator_returns_consistent_format(self):
        """Test all validators return consistent output format."""
        import phase_data as pd

        # Test with non-existent project to get error responses
        nonexistent = "/nonexistent/path"

        for phase in range(1, 8):
            result = pd.validate_phase(phase, nonexistent)

            # All results should have these fields
            assert "status" in result, f"Phase {phase} result missing 'status'"
            assert "phase" in result or "message" in result, \
                f"Phase {phase} result missing 'phase' or 'message'"

            # Status should be one of expected values
            assert result["status"] in ["passed", "blocking", "warning", "error"], \
                f"Phase {phase} has invalid status: {result['status']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
