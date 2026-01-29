"""
Pytest configuration and fixtures for threat-modeling-v3 tests.

Provides:
- Project path fixtures
- Phase working directory setup/teardown
- Mock data generators
- Test data paths
"""

import os
import sys
import shutil
import tempfile
from pathlib import Path
from typing import Generator, Dict, Any

import pytest

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Get project root directory."""
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def scripts_dir(project_root: Path) -> Path:
    """Get scripts directory."""
    return project_root / "scripts"


@pytest.fixture(scope="session")
def knowledge_dir(project_root: Path) -> Path:
    """Get knowledge directory."""
    return project_root / "knowledge"


@pytest.fixture(scope="session")
def phases_dir(project_root: Path) -> Path:
    """Get phases directory."""
    return project_root / "phases"


@pytest.fixture(scope="session")
def contracts_dir(project_root: Path) -> Path:
    """Get contracts directory."""
    return project_root / "contracts"


@pytest.fixture
def temp_working_dir() -> Generator[Path, None, None]:
    """Create temporary working directory for tests."""
    temp_dir = tempfile.mkdtemp(prefix="phase_working_")
    yield Path(temp_dir)
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_session_meta() -> Dict[str, Any]:
    """Generate mock session metadata."""
    return {
        "session_id": "20260130-120000",
        "project_name": "TEST-PROJECT",
        "project_path": "/tmp/test-project",
        "started_at": "2026-01-30T12:00:00Z",
        "phases_completed": [],
        "current_phase": 1,
        "skill_version": "3.0.0",
    }


@pytest.fixture
def mock_threat_inventory() -> Dict[str, Any]:
    """Generate mock P5 threat inventory for count conservation tests."""
    return {
        "threats": [
            {"id": "T-S-P-001-001", "stride_type": "S", "element_id": "P-001", "title": "Session Hijacking"},
            {"id": "T-T-DS-001-001", "stride_type": "T", "element_id": "DS-001", "title": "SQL Injection"},
            {"id": "T-I-DF-001-001", "stride_type": "I", "element_id": "DF-001", "title": "Data Exposure"},
            {"id": "T-D-P-002-001", "stride_type": "D", "element_id": "P-002", "title": "Resource Exhaustion"},
            {"id": "T-E-P-001-001", "stride_type": "E", "element_id": "P-001", "title": "Privilege Escalation"},
        ],
        "summary": {
            "total": 5,
            "by_stride": {"S": 1, "T": 1, "R": 0, "I": 1, "D": 1, "E": 1},
            "by_element_type": {"process": 3, "datastore": 1, "dataflow": 1},
        },
    }


@pytest.fixture
def mock_validated_risks() -> Dict[str, Any]:
    """Generate mock P6 validated risks matching threat inventory."""
    return {
        "risk_summary": {
            "total_identified": 5,
            "total_verified": 3,
            "total_theoretical": 1,
            "total_pending": 0,
            "total_excluded": 1,
        },
        "risk_details": [
            {
                "id": "VR-001",
                "title": "Session Hijacking Risk",
                "threat_refs": ["T-S-P-001-001"],
                "priority": "P1",
                "validation": {"status": "verified"},
            },
            {
                "id": "VR-002",
                "title": "SQL Injection Risk",
                "threat_refs": ["T-T-DS-001-001"],
                "priority": "P0",
                "validation": {"status": "verified"},
            },
            {
                "id": "VR-003",
                "title": "Combined Information & DoS Risk",
                "threat_refs": ["T-I-DF-001-001", "T-D-P-002-001"],
                "priority": "P1",
                "validation": {"status": "verified"},
            },
            {
                "id": "VR-004",
                "title": "Theoretical Privilege Escalation",
                "threat_refs": ["T-E-P-001-001"],
                "priority": "P2",
                "validation": {"status": "theoretical"},
            },
        ],
        "excluded_threats": [],
    }


@pytest.fixture
def mock_dfd_elements() -> Dict[str, Any]:
    """Generate mock P2 DFD elements."""
    return {
        "external_interactors": [
            {"id": "EI-001", "name": "Web User", "type": "Human"},
            {"id": "EI-002", "name": "API Client", "type": "ExternalSystem"},
        ],
        "processes": [
            {"id": "P-001", "name": "API Gateway", "auth_required": True},
            {"id": "P-002", "name": "Auth Service", "auth_required": True},
            {"id": "P-003", "name": "Data Service", "auth_required": True},
        ],
        "data_stores": [
            {"id": "DS-001", "name": "User Database", "sensitivity": "CRITICAL"},
            {"id": "DS-002", "name": "Session Cache", "sensitivity": "HIGH"},
        ],
        "data_flows": [
            {"id": "DF-001", "from": "EI-001", "to": "P-001", "data": "HTTP Request", "encrypted": True},
            {"id": "DF-002", "from": "P-001", "to": "P-002", "data": "Auth Request", "encrypted": True},
            {"id": "DF-003", "from": "P-002", "to": "DS-001", "data": "User Query", "encrypted": True},
        ],
        "l1_coverage": {
            "total_entry_points": 5,
            "analyzed": 5,
            "coverage_percentage": 100,
        },
    }


@pytest.fixture
def mock_trust_boundaries() -> Dict[str, Any]:
    """Generate mock P3 trust boundaries."""
    return {
        "boundaries": [
            {"id": "TB-001", "name": "Internet Boundary", "type": "Network", "inside": ["P-001"], "outside": ["EI-001", "EI-002"]},
            {"id": "TB-002", "name": "Service Mesh", "type": "Process", "inside": ["P-002", "P-003"], "outside": ["P-001"]},
            {"id": "TB-003", "name": "Data Zone", "type": "Data", "inside": ["DS-001", "DS-002"], "outside": ["P-002", "P-003"]},
        ],
        "interfaces": [
            {"id": "IF-001", "name": "Public API", "type": "API", "boundary_id": "TB-001"},
            {"id": "IF-002", "name": "Internal gRPC", "type": "API", "boundary_id": "TB-002"},
        ],
        "data_nodes": [
            {"id": "DN-001", "name": "User Credentials", "data_type": "credentials", "sensitivity": "CRITICAL"},
            {"id": "DN-002", "name": "Session Tokens", "data_type": "credentials", "sensitivity": "HIGH"},
        ],
        "cross_boundary_flows": [
            {"flow_id": "DF-001", "boundary_id": "TB-001", "direction": "inbound"},
            {"flow_id": "DF-002", "boundary_id": "TB-002", "direction": "inbound"},
        ],
    }


@pytest.fixture
def mock_security_gaps() -> Dict[str, Any]:
    """Generate mock P4 security gaps."""
    return {
        "gaps": [
            {"id": "GAP-001", "domain": "AUTHN", "title": "Weak Password Policy", "severity": "HIGH"},
            {"id": "GAP-002", "domain": "CRYPTO", "title": "Outdated TLS Version", "severity": "MEDIUM"},
            {"id": "GAP-003", "domain": "LOGGING", "title": "Insufficient Audit Trail", "severity": "MEDIUM"},
            {"id": "GAP-004", "domain": "INPUT", "title": "Missing Input Validation", "severity": "HIGH"},
        ],
        "design_matrix": {
            "AUTHN": {"rating": "Partial", "gaps_count": 1},
            "AUTHZ": {"rating": "Present", "gaps_count": 0},
            "INPUT": {"rating": "Partial", "gaps_count": 1},
            "OUTPUT": {"rating": "Present", "gaps_count": 0},
            "CRYPTO": {"rating": "Partial", "gaps_count": 1},
            "LOGGING": {"rating": "Partial", "gaps_count": 1},
            "ERROR": {"rating": "Present", "gaps_count": 0},
            "API": {"rating": "Present", "gaps_count": 0},
            "DATA": {"rating": "Present", "gaps_count": 0},
            "CONFIG": {"rating": "Present", "gaps_count": 0},
            "INFRA": {"rating": "Present", "gaps_count": 0},
            "SUPPLY": {"rating": "NotAssessed", "gaps_count": 0},
            "AI": {"rating": "NA", "gaps_count": 0},
            "MOBILE": {"rating": "NA", "gaps_count": 0},
            "CLOUD": {"rating": "Present", "gaps_count": 0},
            "AGENTIC": {"rating": "NA", "gaps_count": 0},
        },
    }


@pytest.fixture
def mock_mitigation_plan() -> Dict[str, Any]:
    """Generate mock P7 mitigation plan."""
    return {
        "mitigations": [
            {
                "id": "MIT-001",
                "title": "Implement Strong Password Policy",
                "risk_refs": ["VR-001"],
                "priority": "P1",
                "effort": "MEDIUM",
            },
            {
                "id": "MIT-002",
                "title": "Upgrade TLS Configuration",
                "risk_refs": ["VR-002"],
                "priority": "P0",
                "effort": "LOW",
            },
            {
                "id": "MIT-003",
                "title": "Implement Comprehensive Logging",
                "risk_refs": ["VR-003", "VR-004"],
                "priority": "P2",
                "effort": "HIGH",
            },
        ],
        "roadmap": {
            "immediate": ["MIT-002"],
            "short_term": ["MIT-001"],
            "medium_term": ["MIT-003"],
            "long_term": [],
        },
    }
