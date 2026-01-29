#!/usr/bin/env python3
"""
Phase Data Manager for STRIDE Threat Modeling Workflow.

Manages structured data extraction, storage, and cross-phase querying
for the 8-phase threat modeling workflow.

Design Philosophy (per SKILL.md First Principles):
- Context is a shared resource: Script queries replace re-reading Markdown
- Claude is smart: LLM does analysis, script does data management
- Progressive disclosure: Query on-demand, don't preload
- Scripts are black boxes: Execution doesn't consume context, only output does
- Freedom matches task fragility: ID generation by script, descriptions by LLM

Primary Approach (Option C):
- LLM outputs Markdown with embedded ```yaml:{block_name} blocks
- This script extracts, validates, and stores structured data
- Cross-phase queries return focused summaries

Backup Approach (Option B):
- LLM outputs JSON directly (triggered by explicit prompt)
- This script stores JSON input as-is

Usage:
    # Extract YAML blocks from Markdown report
    python phase_data.py --extract P1-PROJECT-UNDERSTANDING.md --phase 1

    # Query phase data
    python phase_data.py --query --phase 1 --type entry_points
    python phase_data.py --query --phase 2 --element P-001
    python phase_data.py --query --phase 5 --threats-for-element P-013
    python phase_data.py --query --phase 1 --summary

    # Validate phase completion
    python phase_data.py --validate --phase 1 --checklist
    python phase_data.py --validate --phase 2 --l1-coverage

    # Store JSON directly (Option B backup)
    python phase_data.py --store --phase 5 --input-json threats.json

    # Cross-phase aggregation
    python phase_data.py --aggregate --phases 1,2,5 --format summary

    # Initialize session
    python phase_data.py --init --project "OPEN-WEBUI" --path /path/to/project

Output: JSON format for integration with threat modeling workflow.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import yaml


# ============================================================================
# Configuration
# ============================================================================

SCHEMA_VERSION = "2.2.2"
SESSION_SCHEMA_VERSION = "2.2.2"  # Version for session management

# Standard YAML block names per phase (from WORKFLOW.md v2.2.2)
# NOTE: l1_coverage is EMBEDDED inside data_flows block, not extracted separately
# NOTE: P3/P4 blocks are output as Markdown tables, not YAML blocks (per WORKFLOW.md)
PHASE_BLOCKS = {
    1: ["module_inventory", "entry_point_inventory", "discovery_checklist"],
    2: ["dfd_elements", "data_flows"],  # l1_coverage is embedded in data_flows
    3: ["trust_boundaries", "interfaces", "data_nodes", "cross_boundary_flows"],
    4: ["security_gaps", "design_matrix"],
    5: ["threat_inventory"],
    6: ["validated_risks", "attack_paths", "attack_chains", "poc_details"],
    7: ["mitigation_plan", "roadmap"],
}

# Required blocks per phase (validation gates)
# These are the minimum required blocks that MUST be present for validation to pass
REQUIRED_BLOCKS = {
    1: ["module_inventory", "entry_point_inventory", "discovery_checklist"],
    2: ["dfd_elements", "data_flows"],  # l1_coverage validated separately from data_flows content
    3: ["trust_boundaries"],  # interfaces, data_nodes, cross_boundary_flows are optional
    4: ["security_gaps"],     # design_matrix validated separately
    5: ["threat_inventory"],
    6: ["validated_risks"],   # attack_paths, poc_details validated separately
    7: ["mitigation_plan"],   # roadmap validated separately
}

# Phase dependency matrix for Phase End Protocol
# Defines what each phase requires from previous phases and how to query that data
PHASE_DEPENDENCIES = {
    1: {"requires": [], "query": None, "description": "Initial discovery - no dependencies"},
    2: {"requires": [1], "query": "--query --phase 1 --summary", "description": "Requires entry points from P1"},
    3: {"requires": [2], "query": "--query --phase 2 --summary", "description": "Requires DFD elements from P2"},
    4: {"requires": [1, 2, 3], "query": "--aggregate --phases 1,2,3 --format summary", "description": "Requires discovery, DFD, and trust boundaries"},
    5: {"requires": [2], "query": "--query --phase 2 --type dfd", "description": "Requires DFD for STRIDE analysis"},
    6: {"requires": [5], "query": "--query --phase 5 --summary", "description": "Requires threat inventory from P5"},
    7: {"requires": [6], "query": "--query --phase 6 --summary", "description": "Requires validated risks from P6"},
    8: {"requires": [1, 2, 3, 4, 5, 6, 7], "query": "--aggregate --phases 1,2,3,4,5,6,7 --format summary", "description": "Requires all phases for final report"},
}

# Entry point types for discovery checklist validation
ENTRY_POINT_TYPES = [
    "rest_api",
    "internal_api",
    "graphql",
    "websocket",
    "cron_jobs",
    "message_queue",
    "webhooks",
    "file_upload",
    "health_endpoints",
    "debug_endpoints",
]

# YAML block extraction pattern
# Matches ```yaml:{block_name} ... ``` blocks
YAML_BLOCK_PATTERN = re.compile(
    r'```yaml:(\w+)\s*\n(.*?)```',
    re.DOTALL | re.MULTILINE
)

# ============================================================================
# ID Format Validation Patterns (migrated from validate_count_conservation.py)
# ============================================================================

ID_PATTERNS = {
    # P1 Entity Patterns
    'module': re.compile(r'^M-\d{3}$'),                       # M-001
    'entry_point': re.compile(r'^EP-\d{3}$'),                 # EP-001
    'finding': re.compile(r'^F-P[1-8]-\d{3}$'),              # F-P1-001

    # P2 DFD Element Patterns
    'external_interactor': re.compile(r'^EI-\d{3}$'),        # EI-001
    'process': re.compile(r'^P-\d{3}$'),                     # P-001
    'data_store': re.compile(r'^DS-\d{3}$'),                 # DS-001
    'data_flow': re.compile(r'^DF-\d{3}$'),                  # DF-001

    # P3 Trust Boundary Patterns
    'trust_boundary': re.compile(r'^TB-\d{3}$'),             # TB-001
    'interface': re.compile(r'^IF-\d{3}$'),                  # IF-001
    'data_node': re.compile(r'^DN-\d{3}$'),                  # DN-001

    # P4 Security Gap Patterns
    'security_gap': re.compile(r'^GAP-\d{3}$'),              # GAP-001

    # P5 Threat Patterns
    'threat': re.compile(r'^T-[STRIDE]-[A-Z]+-\d{3}-\d{3}$'),  # T-S-P-001-001
    'threat_alt': re.compile(r'^T-[STRIDE]-[A-Z]+\d+-\d{3}$'), # T-S-P1-001 (legacy format)

    # P6 Risk Patterns
    'validated_risk': re.compile(r'^VR-\d{3}$'),             # VR-001
    'poc': re.compile(r'^POC-\d{3}$'),                       # POC-001
    'attack_path': re.compile(r'^AP-\d{3}$'),                # AP-001
    'attack_chain': re.compile(r'^AC-\d{3}$'),               # AC-001

    # P7 Mitigation Patterns
    'mitigation': re.compile(r'^MIT-\d{3}$'),                # MIT-001 (changed from M-xxx)

    # Forbidden formats
    'forbidden_risk': re.compile(r'^RISK-\d+$'),              # RISK-001 (should be VR-xxx)
    'forbidden_threat': re.compile(r'^T-[STRIDE]-[A-Z]{3,}-\d{3}$'),  # T-E-RCE-001 (missing ElementID)
    'forbidden_mitigation': re.compile(r'^M-\d{3}$'),         # M-001 collision with Module
}

# Security design domains for P4 validation (16 domains per SKILL.md)
SECURITY_DOMAINS = [
    "AUTHN", "AUTHZ", "INPUT", "OUTPUT", "CRYPTO", "LOGGING",
    "ERROR", "API", "DATA", "CONFIG", "INFRA", "SUPPLY",
    "AI", "MOBILE", "CLOUD", "AGENTIC"
]

# STRIDE categories for threat validation
STRIDE_CATEGORIES = ['S', 'T', 'R', 'I', 'D', 'E']

# Final reports that should contain VR entries (for CP3 validation)
FINAL_REPORTS = [
    'RISK-INVENTORY',
    'RISK-ASSESSMENT-REPORT',
    'MITIGATION-MEASURES',
    'PENETRATION-TEST-PLAN',
]


# ============================================================================
# Directory Structure Management
# ============================================================================

def get_phase_working_dir(project_root: str) -> Path:
    """Get the .phase_working directory path."""
    return Path(project_root) / "Risk_Assessment_Report" / ".phase_working"


def get_phase_data_dir(project_root: str, session_id: Optional[str] = None) -> Path:
    """
    Get the phase data directory path.

    If session_id is provided, returns the session-specific data directory.
    If not provided, attempts to get the current active session's data directory.
    Falls back to legacy structure if no session exists.

    Args:
        project_root: Project root directory
        session_id: Optional specific session ID

    Returns:
        Path to the data directory
    """
    phase_working = get_phase_working_dir(project_root)

    # If session_id provided, use that session's data directory
    if session_id:
        return phase_working / session_id / "data"

    # Try to get current session
    current_session_dir = get_current_session_dir(project_root)
    if current_session_dir:
        return current_session_dir / "data"

    # Fallback to legacy structure
    return phase_working / "phase_data"


def get_current_session_dir(project_root: str) -> Optional[Path]:
    """
    Get the current active session directory.

    Reads _session_meta.yaml to find the current active session.

    Args:
        project_root: Project root directory

    Returns:
        Path to the current session directory, or None if no active session
    """
    phase_working = get_phase_working_dir(project_root)
    meta_file = phase_working / "_session_meta.yaml"

    if not meta_file.exists():
        return None

    try:
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = yaml.safe_load(f)

        if not meta:
            return None

        current_session = meta.get("current_session", {})
        session_id = current_session.get("session_id")

        if not session_id:
            return None

        session_dir = phase_working / session_id
        if session_dir.exists():
            return session_dir

    except (yaml.YAMLError, IOError):
        pass

    return None


def ensure_directories(project_root: str, session_id: Optional[str] = None) -> Dict[str, Path]:
    """
    Ensure all required directories exist.

    Args:
        project_root: Project root directory
        session_id: Optional session ID for session-specific directories

    Returns:
        Dict with directory paths
    """
    phase_working = get_phase_working_dir(project_root)
    phase_working.mkdir(parents=True, exist_ok=True)

    if session_id:
        # Session-specific structure
        session_dir = phase_working / session_id
        data_dir = session_dir / "data"
        session_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)
        return {
            "phase_working": phase_working,
            "session_dir": session_dir,
            "phase_data": data_dir,
        }
    else:
        # Legacy structure or auto-detect current session
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            data_dir = current_session_dir / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            return {
                "phase_working": phase_working,
                "session_dir": current_session_dir,
                "phase_data": data_dir,
            }
        else:
            # Fallback to legacy
            phase_data = phase_working / "phase_data"
            phase_data.mkdir(parents=True, exist_ok=True)
            return {
                "phase_working": phase_working,
                "phase_data": phase_data,
            }


# ============================================================================
# Session Management (Multi-Version)
# ============================================================================

def _generate_session_id(project_name: str) -> str:
    """
    Generate a session ID in the format {PROJECT}-YYYYMMDD_HHMMSS.

    Args:
        project_name: Project name (will be uppercased and normalized)

    Returns:
        Session ID string
    """
    # Normalize project name: uppercase, replace spaces/underscores with hyphens
    normalized = project_name.upper().replace("_", "-").replace(" ", "-")
    # Remove consecutive hyphens
    while "--" in normalized:
        normalized = normalized.replace("--", "-")
    # Remove leading/trailing hyphens
    normalized = normalized.strip("-")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{normalized}-{timestamp}"


def _detect_legacy_session(project_root: str) -> bool:
    """
    Detect legacy single-file session structure.

    Legacy structure has:
    - .phase_working/_session.yaml (not in a subdirectory)
    - .phase_working/phase_data/ directory

    New structure has:
    - .phase_working/_session_meta.yaml
    - .phase_working/{SESSION_ID}/_session.yaml
    - .phase_working/{SESSION_ID}/data/

    Args:
        project_root: Project root directory

    Returns:
        True if legacy structure detected, False otherwise
    """
    phase_working = get_phase_working_dir(project_root)

    # Check for legacy _session.yaml at top level
    legacy_session = phase_working / "_session.yaml"
    legacy_data = phase_working / "phase_data"

    # Check for new structure markers
    new_meta = phase_working / "_session_meta.yaml"

    # Legacy if: has old _session.yaml AND phase_data/ AND no _session_meta.yaml
    if legacy_session.exists() and legacy_data.exists() and not new_meta.exists():
        return True

    return False


def _load_session_meta(project_root: str) -> Optional[Dict]:
    """
    Load the global session metadata file.

    Args:
        project_root: Project root directory

    Returns:
        Session metadata dict, or None if not found
    """
    meta_file = get_phase_working_dir(project_root) / "_session_meta.yaml"

    if not meta_file.exists():
        return None

    try:
        with open(meta_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except (yaml.YAMLError, IOError):
        return None


def _save_session_meta(project_root: str, meta: Dict) -> None:
    """
    Save the global session metadata file.

    Args:
        project_root: Project root directory
        meta: Session metadata dict
    """
    phase_working = get_phase_working_dir(project_root)
    phase_working.mkdir(parents=True, exist_ok=True)
    meta_file = phase_working / "_session_meta.yaml"

    with open(meta_file, "w", encoding="utf-8") as f:
        yaml.dump(meta, f, allow_unicode=True, default_flow_style=False, sort_keys=False)


def _update_session_meta(
    project_root: str,
    session_id: str,
    project_name: str,
    action: str,
    current_phase: Optional[int] = None,
    phases_completed: Optional[List[int]] = None
) -> None:
    """
    Update global _session_meta.yaml.

    Args:
        project_root: Project root directory
        session_id: Session ID
        project_name: Project name
        action: Action type - "create", "resume", "update", "complete", "abort"
        current_phase: Optional current phase number
        phases_completed: Optional list of completed phases
    """
    now = datetime.now().isoformat()
    meta = _load_session_meta(project_root)

    if not meta:
        # Initialize new meta structure
        meta = {
            "schema_version": SESSION_SCHEMA_VERSION,
            "project_name": project_name,
            "current_session": None,
            "sessions": [],
            "last_completed": None,
        }

    # Update project name (use provided or keep existing)
    if project_name:
        meta["project_name"] = project_name

    # Find existing session entry
    session_entry = None
    for s in meta.get("sessions", []):
        if s.get("session_id") == session_id:
            session_entry = s
            break

    if action == "create":
        # Create new session entry
        new_entry = {
            "session_id": session_id,
            "status": "in_progress",
            "phases_completed": phases_completed or [],
            "started_at": now,
            "ended_at": None,
        }
        meta["sessions"].append(new_entry)

        # Set as current session
        meta["current_session"] = {
            "session_id": session_id,
            "status": "in_progress",
            "current_phase": current_phase or 1,
            "started_at": now,
        }

    elif action == "resume":
        if session_entry:
            session_entry["status"] = "in_progress"
            meta["current_session"] = {
                "session_id": session_id,
                "status": "in_progress",
                "current_phase": current_phase or session_entry.get("phases_completed", [])[-1] + 1 if session_entry.get("phases_completed") else 1,
                "started_at": session_entry.get("started_at", now),
            }

    elif action == "update":
        if session_entry:
            if phases_completed:
                session_entry["phases_completed"] = sorted(list(set(phases_completed)))
            if current_phase:
                if meta.get("current_session", {}).get("session_id") == session_id:
                    meta["current_session"]["current_phase"] = current_phase

    elif action == "complete":
        if session_entry:
            session_entry["status"] = "completed"
            session_entry["ended_at"] = now
            if phases_completed:
                session_entry["phases_completed"] = sorted(list(set(phases_completed)))
            meta["last_completed"] = session_id
            if meta.get("current_session", {}).get("session_id") == session_id:
                meta["current_session"] = None

    elif action == "abort":
        if session_entry:
            session_entry["status"] = "aborted"
            session_entry["ended_at"] = now
            if meta.get("current_session", {}).get("session_id") == session_id:
                meta["current_session"] = None

    _save_session_meta(project_root, meta)


def check_session(project_root: str) -> Dict:
    """
    Check for incomplete sessions and return status.

    Scans for sessions with status "in_progress" and returns detailed info.

    Args:
        project_root: Project root directory

    Returns:
        Dict with session status:
        - has_incomplete: bool
        - incomplete_sessions: list of incomplete session info
        - current_session: current active session info or None
        - legacy_detected: bool if legacy structure found
    """
    result = {
        "has_incomplete": False,
        "incomplete_sessions": [],
        "current_session": None,
        "legacy_detected": False,
        "total_sessions": 0,
    }

    # Check for legacy structure
    if _detect_legacy_session(project_root):
        result["legacy_detected"] = True
        phase_working = get_phase_working_dir(project_root)
        legacy_session = phase_working / "_session.yaml"

        try:
            with open(legacy_session, "r", encoding="utf-8") as f:
                legacy_data = yaml.safe_load(f)
            if legacy_data:
                result["has_incomplete"] = True
                result["incomplete_sessions"].append({
                    "session_id": legacy_data.get("session_id", "legacy"),
                    "type": "legacy",
                    "project_name": legacy_data.get("project_name"),
                    "current_phase": legacy_data.get("current_phase", 1),
                    "phases_completed": legacy_data.get("phases_completed", []),
                    "started_at": legacy_data.get("started_at"),
                    "message": "Legacy single-file session detected. Use --migrate-session to upgrade.",
                })
        except (yaml.YAMLError, IOError):
            pass

        return result

    # Check new session structure
    meta = _load_session_meta(project_root)
    if not meta:
        return result

    result["total_sessions"] = len(meta.get("sessions", []))

    # Get current session
    if meta.get("current_session"):
        result["current_session"] = meta["current_session"]

    # Find all incomplete sessions
    for session in meta.get("sessions", []):
        if session.get("status") == "in_progress":
            result["has_incomplete"] = True
            session_info = {
                "session_id": session.get("session_id"),
                "type": "multi_version",
                "phases_completed": session.get("phases_completed", []),
                "started_at": session.get("started_at"),
            }

            # Load session-specific data for more details
            session_dir = get_phase_working_dir(project_root) / session.get("session_id", "")
            session_file = session_dir / "_session.yaml"
            if session_file.exists():
                try:
                    with open(session_file, "r", encoding="utf-8") as f:
                        session_data = yaml.safe_load(f)
                    if session_data:
                        session_info["current_phase"] = session_data.get("current_phase", 1)
                        session_info["project_name"] = session_data.get("project_name")
                except (yaml.YAMLError, IOError):
                    pass

            result["incomplete_sessions"].append(session_info)

    return result


def create_session(project_name: str, project_path: str) -> Dict:
    """
    Create a new session with subdirectory structure.

    Creates:
    - .phase_working/_session_meta.yaml (updated)
    - .phase_working/{SESSION_ID}/_session.yaml
    - .phase_working/{SESSION_ID}/data/

    Args:
        project_name: Project name
        project_path: Project path

    Returns:
        Dict with session creation result
    """
    session_id = _generate_session_id(project_name)
    now = datetime.now().isoformat()

    # Create directory structure
    dirs = ensure_directories(project_path, session_id)

    # Create session-specific _session.yaml
    session_data = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "project_name": project_name,
        "project_path": project_path,
        "started_at": now,
        "skill_version": SCHEMA_VERSION,
        "phases_completed": [],
        "current_phase": 1,
        "last_updated": now,
        "extraction_status": {
            f"phase{i}": {"extracted": False, "entities": 0}
            for i in range(1, 9)
        },
    }

    session_file = dirs["session_dir"] / "_session.yaml"
    with open(session_file, "w", encoding="utf-8") as f:
        yaml.dump(session_data, f, allow_unicode=True, default_flow_style=False)

    # Update global session meta
    _update_session_meta(
        project_path,
        session_id,
        project_name,
        "create",
        current_phase=1,
        phases_completed=[]
    )

    return {
        "status": "success",
        "action": "create_session",
        "session_id": session_id,
        "session_dir": str(dirs["session_dir"]),
        "data_dir": str(dirs["phase_data"]),
        "project_name": project_name,
        "message": f"Session created: {session_id}",
    }


def resume_session(project_root: str, session_id: Optional[str] = None) -> Dict:
    """
    Resume an incomplete session.

    If session_id is not provided, resumes the most recent incomplete session.

    Args:
        project_root: Project root directory
        session_id: Optional specific session ID to resume

    Returns:
        Dict with resume result
    """
    # Check for incomplete sessions
    check_result = check_session(project_root)

    if not check_result["has_incomplete"]:
        return {
            "status": "error",
            "action": "resume_session",
            "message": "No incomplete sessions found to resume.",
        }

    # Handle legacy session
    if check_result["legacy_detected"] and not session_id:
        return {
            "status": "error",
            "action": "resume_session",
            "message": "Legacy session detected. Use --migrate-session first to convert to new format.",
            "legacy_info": check_result["incomplete_sessions"][0] if check_result["incomplete_sessions"] else None,
        }

    # Find session to resume
    target_session = None

    if session_id:
        # Find specific session
        for s in check_result["incomplete_sessions"]:
            if s["session_id"] == session_id:
                target_session = s
                break
        if not target_session:
            return {
                "status": "error",
                "action": "resume_session",
                "message": f"Session '{session_id}' not found or not incomplete.",
                "available_sessions": [s["session_id"] for s in check_result["incomplete_sessions"]],
            }
    else:
        # Get most recent incomplete (last in list, sorted by started_at)
        incomplete = sorted(
            check_result["incomplete_sessions"],
            key=lambda x: x.get("started_at", ""),
            reverse=True
        )
        if incomplete:
            target_session = incomplete[0]

    if not target_session:
        return {
            "status": "error",
            "action": "resume_session",
            "message": "No resumable session found.",
        }

    # Resume the session
    target_id = target_session["session_id"]

    # Update session meta
    meta = _load_session_meta(project_root)
    if meta:
        for s in meta.get("sessions", []):
            if s.get("session_id") == target_id:
                current_phase = max(s.get("phases_completed", [0])) + 1 if s.get("phases_completed") else 1
                break
        else:
            current_phase = target_session.get("current_phase", 1)

        _update_session_meta(
            project_root,
            target_id,
            target_session.get("project_name", ""),
            "resume",
            current_phase=current_phase
        )

    # Load session data
    session_dir = get_phase_working_dir(project_root) / target_id
    session_file = session_dir / "_session.yaml"

    session_data = None
    if session_file.exists():
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                session_data = yaml.safe_load(f)
        except (yaml.YAMLError, IOError):
            pass

    return {
        "status": "success",
        "action": "resume_session",
        "session_id": target_id,
        "session_dir": str(session_dir),
        "current_phase": session_data.get("current_phase") if session_data else target_session.get("current_phase", 1),
        "phases_completed": session_data.get("phases_completed") if session_data else target_session.get("phases_completed", []),
        "project_name": session_data.get("project_name") if session_data else target_session.get("project_name"),
        "message": f"Session resumed: {target_id}",
    }


def migrate_legacy_session(project_root: str) -> Dict:
    """
    Migrate legacy session to new multi-version structure.

    Converts:
    - .phase_working/_session.yaml → .phase_working/{SESSION_ID}/_session.yaml
    - .phase_working/phase_data/ → .phase_working/{SESSION_ID}/data/

    Creates:
    - .phase_working/_session_meta.yaml

    Args:
        project_root: Project root directory

    Returns:
        Dict with migration result
    """
    if not _detect_legacy_session(project_root):
        return {
            "status": "error",
            "action": "migrate_legacy_session",
            "message": "No legacy session structure detected.",
        }

    phase_working = get_phase_working_dir(project_root)
    legacy_session_file = phase_working / "_session.yaml"
    legacy_data_dir = phase_working / "phase_data"

    # Load legacy session data
    try:
        with open(legacy_session_file, "r", encoding="utf-8") as f:
            legacy_data = yaml.safe_load(f)
    except (yaml.YAMLError, IOError) as e:
        return {
            "status": "error",
            "action": "migrate_legacy_session",
            "message": f"Failed to read legacy session: {e}",
        }

    if not legacy_data:
        return {
            "status": "error",
            "action": "migrate_legacy_session",
            "message": "Legacy session file is empty.",
        }

    # Generate session ID based on legacy data
    project_name = legacy_data.get("project_name", "UNKNOWN")
    legacy_session_id = legacy_data.get("session_id", "")

    # Try to parse timestamp from legacy session_id (format: YYYYMMDD-HHMMSS)
    if legacy_session_id and re.match(r'\d{8}-\d{6}', legacy_session_id):
        # Convert old format to new format
        timestamp = legacy_session_id.replace("-", "_")
        new_session_id = f"{project_name.upper()}-{timestamp}"
    else:
        # Use legacy start time or current time
        started_at = legacy_data.get("started_at", "")
        if started_at:
            try:
                dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                timestamp = dt.strftime("%Y%m%d_%H%M%S")
            except ValueError:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_session_id = f"{project_name.upper()}-{timestamp}"

    # Create new session directory
    new_session_dir = phase_working / new_session_id
    new_data_dir = new_session_dir / "data"

    new_session_dir.mkdir(parents=True, exist_ok=True)
    new_data_dir.mkdir(parents=True, exist_ok=True)

    # Copy phase data files
    migrated_files = []
    if legacy_data_dir.exists():
        import shutil
        for file_path in legacy_data_dir.glob("*.yaml"):
            dest = new_data_dir / file_path.name
            shutil.copy2(file_path, dest)
            migrated_files.append(file_path.name)

    # Update legacy session data and save to new location
    legacy_data["session_id"] = new_session_id
    legacy_data["migrated_from"] = "legacy"
    legacy_data["migrated_at"] = datetime.now().isoformat()

    new_session_file = new_session_dir / "_session.yaml"
    with open(new_session_file, "w", encoding="utf-8") as f:
        yaml.dump(legacy_data, f, allow_unicode=True, default_flow_style=False)

    # Create _session_meta.yaml
    phases_completed = legacy_data.get("phases_completed", [])
    current_phase = legacy_data.get("current_phase", 1)

    _update_session_meta(
        project_root,
        new_session_id,
        project_name,
        "create",
        current_phase=current_phase,
        phases_completed=phases_completed
    )

    # Archive legacy files (rename, don't delete)
    legacy_session_file.rename(phase_working / "_session.yaml.legacy")
    if legacy_data_dir.exists():
        legacy_data_dir.rename(phase_working / "phase_data.legacy")

    return {
        "status": "success",
        "action": "migrate_legacy_session",
        "old_session_id": legacy_session_id,
        "new_session_id": new_session_id,
        "session_dir": str(new_session_dir),
        "data_dir": str(new_data_dir),
        "files_migrated": migrated_files,
        "project_name": project_name,
        "phases_completed": phases_completed,
        "current_phase": current_phase,
        "message": f"Successfully migrated legacy session to {new_session_id}",
    }


def list_sessions(project_root: str) -> Dict:
    """
    List all sessions for a project.

    Args:
        project_root: Project root directory

    Returns:
        Dict with list of all sessions and their status
    """
    result = {
        "sessions": [],
        "current_session": None,
        "total": 0,
        "completed": 0,
        "in_progress": 0,
        "aborted": 0,
        "legacy_detected": False,
    }

    # Check for legacy
    if _detect_legacy_session(project_root):
        result["legacy_detected"] = True

    # Load session meta
    meta = _load_session_meta(project_root)
    if not meta:
        if result["legacy_detected"]:
            result["message"] = "Only legacy session found. Use --migrate-session to upgrade."
        else:
            result["message"] = "No sessions found."
        return result

    result["current_session"] = meta.get("current_session")
    result["last_completed"] = meta.get("last_completed")

    for session in meta.get("sessions", []):
        session_info = {
            "session_id": session.get("session_id"),
            "status": session.get("status"),
            "phases_completed": session.get("phases_completed", []),
            "started_at": session.get("started_at"),
            "ended_at": session.get("ended_at"),
        }

        # Load additional session details if available
        session_dir = get_phase_working_dir(project_root) / session.get("session_id", "")
        session_file = session_dir / "_session.yaml"
        if session_file.exists():
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    session_data = yaml.safe_load(f)
                if session_data:
                    session_info["project_name"] = session_data.get("project_name")
                    session_info["current_phase"] = session_data.get("current_phase")
            except (yaml.YAMLError, IOError):
                pass

        result["sessions"].append(session_info)

        # Count by status
        status = session.get("status", "")
        if status == "completed":
            result["completed"] += 1
        elif status == "in_progress":
            result["in_progress"] += 1
        elif status == "aborted":
            result["aborted"] += 1

    result["total"] = len(result["sessions"])

    return result


def init_session(project_name: str, project_path: str, force: bool = False) -> Dict:
    """
    Initialize or update session metadata.

    Checks for incomplete sessions first. If found, returns a warning
    unless force=True is specified.

    Creates new multi-version session structure:
    - .phase_working/_session_meta.yaml
    - .phase_working/{SESSION_ID}/_session.yaml
    - .phase_working/{SESSION_ID}/data/

    Args:
        project_name: Project name
        project_path: Project path
        force: If True, create new session even if incomplete sessions exist

    Returns:
        Dict with session initialization result
    """
    # Check for incomplete sessions
    check_result = check_session(project_path)

    # Check for legacy session - suggest migration
    if check_result["legacy_detected"]:
        if not force:
            return {
                "status": "warning",
                "action": "init_session",
                "message": "Legacy session detected. Use --migrate-session to upgrade, or --force to create a new session.",
                "legacy_info": check_result["incomplete_sessions"][0] if check_result["incomplete_sessions"] else None,
                "hint": "Run with --force to ignore and create new session, or --migrate-session to upgrade legacy session.",
            }

    # Check for incomplete multi-version sessions
    if check_result["has_incomplete"] and not check_result["legacy_detected"] and not force:
        return {
            "status": "warning",
            "action": "init_session",
            "message": f"Found {len(check_result['incomplete_sessions'])} incomplete session(s). Use --resume to continue or --force to start new.",
            "incomplete_sessions": [
                {
                    "session_id": s["session_id"],
                    "current_phase": s.get("current_phase", 1),
                    "phases_completed": s.get("phases_completed", []),
                }
                for s in check_result["incomplete_sessions"]
            ],
            "hint": "Run with --resume to continue incomplete session, or --force to start new session.",
        }

    # Create new session
    result = create_session(project_name, project_path)
    result["action"] = "init_session"  # Override action name for compatibility

    return result


def load_session(project_root: str, session_id: Optional[str] = None) -> Optional[Dict]:
    """
    Load existing session metadata.

    If session_id is provided, loads that specific session.
    Otherwise, loads the current active session.
    Falls back to legacy session if no multi-version session exists.

    Args:
        project_root: Project root directory
        session_id: Optional specific session ID to load

    Returns:
        Session data dict, or None if not found
    """
    phase_working = get_phase_working_dir(project_root)

    # If session_id provided, load that session
    if session_id:
        session_file = phase_working / session_id / "_session.yaml"
        if session_file.exists():
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f)
            except (yaml.YAMLError, IOError):
                return None
        return None

    # Try to get current active session
    current_session_dir = get_current_session_dir(project_root)
    if current_session_dir:
        session_file = current_session_dir / "_session.yaml"
        if session_file.exists():
            try:
                with open(session_file, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f)
            except (yaml.YAMLError, IOError):
                pass

    # Fallback to legacy session file
    legacy_session_file = phase_working / "_session.yaml"
    if legacy_session_file.exists():
        try:
            with open(legacy_session_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data:
                    data["_legacy"] = True  # Mark as legacy session
                return data
        except (yaml.YAMLError, IOError):
            pass

    return None


def update_session(project_root: str, updates: Dict, session_id: Optional[str] = None) -> Dict:
    """
    Update session metadata.

    Args:
        project_root: Project root directory
        updates: Dict of fields to update
        session_id: Optional specific session ID to update (defaults to current)

    Returns:
        Dict with update result
    """
    phase_working = get_phase_working_dir(project_root)

    # Determine which session to update
    if session_id:
        session_file = phase_working / session_id / "_session.yaml"
    else:
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            session_file = current_session_dir / "_session.yaml"
            session_id = current_session_dir.name
        else:
            # Fallback to legacy
            session_file = phase_working / "_session.yaml"

    if not session_file.exists():
        return {"error": "Session not initialized. Run --init first."}

    try:
        with open(session_file, "r", encoding="utf-8") as f:
            session_data = yaml.safe_load(f)
    except (yaml.YAMLError, IOError) as e:
        return {"error": f"Failed to read session file: {e}"}

    # Apply updates
    session_data.update(updates)
    session_data["last_updated"] = datetime.now().isoformat()

    with open(session_file, "w", encoding="utf-8") as f:
        yaml.dump(session_data, f, allow_unicode=True, default_flow_style=False)

    # Update session meta if this is a multi-version session
    if session_id and not session_file.parent.name.startswith("."):
        project_name = session_data.get("project_name", "")
        phases_completed = session_data.get("phases_completed", [])
        current_phase = session_data.get("current_phase")
        _update_session_meta(
            project_root,
            session_id,
            project_name,
            "update",
            current_phase=current_phase,
            phases_completed=phases_completed
        )

    return {"status": "success", "updated_fields": list(updates.keys())}


# ============================================================================
# YAML Block Extraction (Option C - Primary Approach)
# ============================================================================

def extract_yaml_blocks(markdown_content: str) -> Dict[str, Any]:
    """
    Extract all ```yaml:{block_name} blocks from Markdown content.

    Returns:
        Dict mapping block_name to parsed YAML content
    """
    blocks = {}
    errors = []

    for match in YAML_BLOCK_PATTERN.finditer(markdown_content):
        block_name = match.group(1)
        yaml_content = match.group(2).strip()

        try:
            parsed = yaml.safe_load(yaml_content)
            blocks[block_name] = parsed
        except yaml.YAMLError as e:
            errors.append({
                "block": block_name,
                "error": str(e),
                "content_preview": yaml_content[:200] + "..." if len(yaml_content) > 200 else yaml_content
            })

    return {
        "blocks": blocks,
        "block_names": list(blocks.keys()),
        "count": len(blocks),
        "errors": errors,
    }


def extract_from_markdown(
    markdown_file: str,
    phase: int,
    project_root: str,
    session_id: Optional[str] = None
) -> Dict:
    """
    Extract YAML blocks from a Markdown report and store them.

    Args:
        markdown_file: Path to the Markdown file
        phase: Phase number (1-8)
        project_root: Project root directory
        session_id: Optional session ID (uses current session if not specified)

    Returns:
        Extraction result with status and stored data info
    """
    # Resolve file path
    md_path = Path(markdown_file)
    if not md_path.is_absolute():
        md_path = Path(project_root) / "Risk_Assessment_Report" / markdown_file

    if not md_path.exists():
        return {"error": f"File not found: {md_path}"}

    # Read and extract
    with open(md_path, "r", encoding="utf-8") as f:
        content = f.read()

    extraction = extract_yaml_blocks(content)

    if extraction["errors"]:
        return {
            "status": "partial",
            "phase": phase,
            "errors": extraction["errors"],
            "blocks_extracted": extraction["count"],
        }

    if extraction["count"] == 0:
        return {
            "status": "warning",
            "phase": phase,
            "message": "No YAML blocks found in Markdown file",
            "hint": "Ensure blocks use ```yaml:{block_name} format",
        }

    # Determine session ID if not provided
    if not session_id:
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            session_id = current_session_dir.name

    # Store extracted data in session-specific or legacy location
    dirs = ensure_directories(project_root, session_id)
    phase_file = dirs["phase_data"] / f"phase{phase}.yaml"

    phase_data = {
        "phase": phase,
        "extracted_at": datetime.now().isoformat(),
        "source_file": str(md_path),
        "blocks": extraction["blocks"],
    }

    if session_id:
        phase_data["session_id"] = session_id

    with open(phase_file, "w", encoding="utf-8") as f:
        yaml.dump(phase_data, f, allow_unicode=True, default_flow_style=False)

    # Update session extraction status
    session = load_session(project_root, session_id)
    if session:
        entity_count = _count_entities(extraction["blocks"])

        # Handle both old and new extraction_status formats
        if "extraction_status" not in session:
            session["extraction_status"] = {}

        session["extraction_status"][f"phase{phase}"] = {
            "extracted": True,
            "entities": entity_count,
            "blocks": extraction["block_names"],
        }

        if "phases_completed" not in session:
            session["phases_completed"] = []

        if phase not in session["phases_completed"]:
            session["phases_completed"].append(phase)
            session["phases_completed"].sort()

        session["current_phase"] = max(session.get("current_phase", 1), phase + 1)
        update_session(project_root, session, session_id)

        # Also update session meta
        if session_id:
            _update_session_meta(
                project_root,
                session_id,
                session.get("project_name", ""),
                "update",
                current_phase=session["current_phase"],
                phases_completed=session["phases_completed"]
            )

    return {
        "status": "success",
        "phase": phase,
        "blocks_extracted": extraction["count"],
        "blocks": {
            name: {"count": _count_items(data)}
            for name, data in extraction["blocks"].items()
        },
        "stored_to": str(phase_file),
        "session_id": session_id,
    }


def _count_entities(blocks: Dict) -> int:
    """Count total entities across all blocks."""
    total = 0
    for data in blocks.values():
        total += _count_items(data)
    return total


def _count_items(data: Any) -> int:
    """Count items in a data structure."""
    if isinstance(data, list):
        return len(data)
    elif isinstance(data, dict):
        # Count items in common list-like keys
        for key in ["modules", "entries", "flows", "threats", "risks", "items"]:
            if key in data and isinstance(data[key], list):
                return len(data[key])
        # Default: count top-level keys
        return len(data)
    return 1


# ============================================================================
# JSON Storage (Option B - Backup Approach)
# ============================================================================

def store_json(
    json_file: str,
    phase: int,
    project_root: str,
    block_name: Optional[str] = None,
    session_id: Optional[str] = None
) -> Dict:
    """
    Store JSON input directly (Option B backup mode).

    Args:
        json_file: Path to JSON file
        phase: Phase number
        project_root: Project root directory
        block_name: Optional block name (defaults to "data")
        session_id: Optional session ID (uses current session if not specified)

    Returns:
        Storage result
    """
    json_path = Path(json_file)

    if not json_path.exists():
        return {"error": f"File not found: {json_path}"}

    with open(json_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON: {e}"}

    # Determine block name
    if block_name is None:
        block_name = "data"

    # Determine session ID if not provided
    if not session_id:
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            session_id = current_session_dir.name

    # Store as phase data
    dirs = ensure_directories(project_root, session_id)
    phase_file = dirs["phase_data"] / f"phase{phase}.yaml"

    # Load existing or create new
    if phase_file.exists():
        with open(phase_file, "r", encoding="utf-8") as f:
            phase_data = yaml.safe_load(f) or {}
    else:
        phase_data = {
            "phase": phase,
            "extracted_at": datetime.now().isoformat(),
            "source_file": str(json_path),
            "blocks": {},
        }

    phase_data["blocks"][block_name] = data
    phase_data["last_updated"] = datetime.now().isoformat()
    if session_id:
        phase_data["session_id"] = session_id

    with open(phase_file, "w", encoding="utf-8") as f:
        yaml.dump(phase_data, f, allow_unicode=True, default_flow_style=False)

    return {
        "status": "success",
        "phase": phase,
        "block_name": block_name,
        "items_stored": _count_items(data),
        "stored_to": str(phase_file),
        "mode": "json_direct (Option B)",
        "session_id": session_id,
    }


# ============================================================================
# Query Functions
# ============================================================================

def load_phase_data(
    phase: int,
    project_root: str,
    session_id: Optional[str] = None
) -> Optional[Dict]:
    """
    Load phase data from storage.

    Args:
        phase: Phase number (1-8)
        project_root: Project root directory
        session_id: Optional specific session ID (uses current session if not specified)

    Returns:
        Phase data dict, or None if not found
    """
    # Get appropriate data directory
    data_dir = get_phase_data_dir(project_root, session_id)
    phase_file = data_dir / f"phase{phase}.yaml"

    if not phase_file.exists():
        # If no session-specific file found and no session_id specified,
        # try legacy location as fallback
        if not session_id:
            legacy_file = get_phase_working_dir(project_root) / "phase_data" / f"phase{phase}.yaml"
            if legacy_file.exists():
                try:
                    with open(legacy_file, "r", encoding="utf-8") as f:
                        return yaml.safe_load(f)
                except (yaml.YAMLError, IOError):
                    pass
        return None

    try:
        with open(phase_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except (yaml.YAMLError, IOError):
        return None


def query_phase(
    phase: int,
    project_root: str,
    query_type: Optional[str] = None,
    element_id: Optional[str] = None,
    block_name: Optional[str] = None,
    summary: bool = False
) -> Dict:
    """
    Query phase data.

    Args:
        phase: Phase number
        project_root: Project root directory
        query_type: Type of data to query (e.g., "entry_points", "threats")
        element_id: Specific element to query
        block_name: Specific block to query
        summary: Return summary instead of full data

    Returns:
        Query result
    """
    phase_data = load_phase_data(phase, project_root)

    if not phase_data:
        return {
            "error": f"No data found for phase {phase}",
            "hint": f"Run --extract on P{phase}-*.md first",
        }

    blocks = phase_data.get("blocks", {})

    # Summary mode: return overview
    if summary:
        return {
            "phase": phase,
            "extracted_at": phase_data.get("extracted_at"),
            "source_file": phase_data.get("source_file"),
            "blocks": {
                name: {
                    "count": _count_items(data),
                    "type": type(data).__name__,
                }
                for name, data in blocks.items()
            },
        }

    # Query specific block
    if block_name:
        if block_name not in blocks:
            return {
                "error": f"Block '{block_name}' not found in phase {phase}",
                "available_blocks": list(blocks.keys()),
            }
        return {
            "phase": phase,
            "block": block_name,
            "data": blocks[block_name],
        }

    # Query by type mapping
    type_block_mapping = {
        "entry_points": "entry_point_inventory",
        "modules": "module_inventory",
        "checklist": "discovery_checklist",
        "dfd": "dfd_elements",
        "flows": "data_flows",
        "threats": "threat_inventory",
        "risks": "validated_risks",
        "attacks": "attack_paths",
        "mitigations": "mitigation_plan",
    }

    if query_type:
        target_block = type_block_mapping.get(query_type, query_type)
        if target_block in blocks:
            return {
                "phase": phase,
                "query_type": query_type,
                "block": target_block,
                "data": blocks[target_block],
            }
        return {
            "error": f"Query type '{query_type}' not found",
            "available_blocks": list(blocks.keys()),
        }

    # Query specific element across blocks
    if element_id:
        results = _find_element(blocks, element_id)
        if results:
            return {
                "phase": phase,
                "element_id": element_id,
                "found_in": results,
            }
        return {
            "error": f"Element '{element_id}' not found in phase {phase}",
        }

    # Default: return all blocks
    return {
        "phase": phase,
        "blocks": blocks,
    }


def _find_element(blocks: Dict, element_id: str) -> List[Dict]:
    """Find element by ID across all blocks."""
    results = []

    for block_name, data in blocks.items():
        found = _search_in_data(data, element_id)
        if found:
            results.append({
                "block": block_name,
                "data": found,
            })

    return results


def _search_in_data(data: Any, element_id: str, path: str = "") -> Optional[Any]:
    """Recursively search for element by ID."""
    if isinstance(data, dict):
        # Check if this dict has matching id
        if data.get("id") == element_id:
            return data
        # Search in values
        for key, value in data.items():
            result = _search_in_data(value, element_id, f"{path}.{key}")
            if result:
                return result
    elif isinstance(data, list):
        for i, item in enumerate(data):
            result = _search_in_data(item, element_id, f"{path}[{i}]")
            if result:
                return result
    return None


def query_threats_for_element(
    element_id: str,
    project_root: str
) -> Dict:
    """Query all threats associated with a specific element."""
    # Load phase 5 (threats) and phase 6 (validated risks)
    p5_data = load_phase_data(5, project_root)
    p6_data = load_phase_data(6, project_root)

    results = {
        "element_id": element_id,
        "threats": [],
        "validated_risks": [],
    }

    if p5_data:
        threats = p5_data.get("blocks", {}).get("threat_inventory", {})
        if isinstance(threats, dict) and "threats" in threats:
            threat_list = threats["threats"]
        elif isinstance(threats, list):
            threat_list = threats
        else:
            threat_list = []

        for threat in threat_list:
            if isinstance(threat, dict):
                if (threat.get("element_id") == element_id or
                    threat.get("target") == element_id or
                    element_id in str(threat.get("affected_elements", []))):
                    results["threats"].append(threat)

    if p6_data:
        risks = p6_data.get("blocks", {}).get("validated_risks", {})
        if isinstance(risks, dict) and "risks" in risks:
            risk_list = risks["risks"]
        elif isinstance(risks, list):
            risk_list = risks
        else:
            risk_list = []

        for risk in risk_list:
            if isinstance(risk, dict):
                if (risk.get("element_id") == element_id or
                    risk.get("threat_id", "").endswith(element_id) or
                    element_id in str(risk.get("affected_elements", []))):
                    results["validated_risks"].append(risk)

    results["threat_count"] = len(results["threats"])
    results["risk_count"] = len(results["validated_risks"])

    return results


# ============================================================================
# Validation Functions
# ============================================================================

def validate_p1_checklist(project_root: str) -> Dict:
    """
    Validate Phase 1 discovery checklist completeness.

    Validation Gates (from design doc):
    - BLOCKING: All checklist items have status in [COMPLETED, NOT_APPLICABLE]
    - BLOCKING: No items with scanned: false
    - WARNING: Sum of counts matches entry_point_inventory length
    """
    phase_data = load_phase_data(1, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 1,
            "message": "Phase 1 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", {})
    checklist = blocks.get("discovery_checklist", {})
    entry_points = blocks.get("entry_point_inventory", {})

    if not checklist:
        return {
            "status": "blocking",
            "phase": 1,
            "gate": "discovery_checklist",
            "message": "Missing discovery_checklist block",
            "action_required": "FIX",
        }

    # Get checklist items
    checklist_items = checklist.get("checklist", checklist)
    if not isinstance(checklist_items, dict):
        return {
            "status": "blocking",
            "phase": 1,
            "gate": "checklist_format",
            "message": "Invalid checklist format",
        }

    blocking_issues = []
    warnings = []

    # Check each entry point type
    for ep_type in ENTRY_POINT_TYPES:
        item = checklist_items.get(ep_type, {})

        # BLOCKING: scanned must be true
        if not item.get("scanned", False):
            blocking_issues.append({
                "type": ep_type,
                "issue": "Not scanned",
                "severity": "BLOCKING",
            })

        # BLOCKING: status must be COMPLETED or NOT_APPLICABLE
        status = item.get("status", "UNKNOWN")
        if status not in ["COMPLETED", "NOT_APPLICABLE"]:
            blocking_issues.append({
                "type": ep_type,
                "issue": f"Invalid status: {status}",
                "severity": "BLOCKING",
            })

    # WARNING: Count consistency check
    summary = checklist.get("summary", {})
    total_from_checklist = summary.get("total_entry_points", 0)

    # Count from entry_point_inventory
    total_from_inventory = 0
    if isinstance(entry_points, dict):
        for key in ["api_entries", "ui_entries", "system_entries", "hidden_entries"]:
            items = entry_points.get(key, [])
            if isinstance(items, list):
                total_from_inventory += len(items)

    if total_from_checklist != total_from_inventory and total_from_inventory > 0:
        warnings.append({
            "issue": "Entry point count mismatch",
            "checklist_count": total_from_checklist,
            "inventory_count": total_from_inventory,
            "severity": "WARNING",
        })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 1,
            "validation": "checklist",
            "passed": False,
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 1 validation FAILED - blocking issues found",
            "options": [
                "[1] FIX - Supplement missing entry discovery",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 1,
        "validation": "checklist",
        "passed": True,
        "coverage": summary.get("coverage", "N/A"),
        "total_entry_points": total_from_checklist,
        "warnings": warnings,
        "message": "Phase 1 validation PASSED",
    }


def validate_p2_l1_coverage(project_root: str) -> Dict:
    """
    Validate Phase 2 L1 interface 100% coverage.

    Validation Gates (from design doc):
    - BLOCKING: l1_coverage.coverage_percentage == 100
    - BLOCKING: All entry_point_analysis.*.analyzed == true
    - WARNING: All entry_point_analysis.*.data_flow_traced == true
    """
    phase_data = load_phase_data(2, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 2,
            "message": "Phase 2 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", {})
    data_flows = blocks.get("data_flows", {})

    # Get L1 coverage info
    l1_coverage = data_flows.get("l1_coverage", {})

    if not l1_coverage:
        return {
            "status": "warning",
            "phase": 2,
            "validation": "l1_coverage",
            "message": "No l1_coverage block found in data_flows",
            "hint": "Ensure P2 report includes l1_coverage in data_flows block",
        }

    blocking_issues = []
    warnings = []

    # BLOCKING: 100% coverage
    coverage_pct = l1_coverage.get("coverage_percentage", 0)
    if coverage_pct < 100:
        blocking_issues.append({
            "issue": "L1 coverage below 100%",
            "current": coverage_pct,
            "required": 100,
            "severity": "BLOCKING",
        })

    # Check individual entry point analysis
    ep_analysis = l1_coverage.get("entry_point_analysis", {})
    unanalyzed = []
    untraced = []

    for ep_id, status in ep_analysis.items():
        if isinstance(status, dict):
            if not status.get("analyzed", False):
                unanalyzed.append(ep_id)
            if not status.get("data_flow_traced", False):
                untraced.append(ep_id)

    # BLOCKING: All must be analyzed
    if unanalyzed:
        blocking_issues.append({
            "issue": "Entry points not analyzed",
            "count": len(unanalyzed),
            "entry_points": unanalyzed[:10],  # Show first 10
            "severity": "BLOCKING",
        })

    # WARNING: Data flow tracing
    if untraced:
        warnings.append({
            "issue": "Entry points without data flow tracing",
            "count": len(untraced),
            "entry_points": untraced[:10],
            "severity": "WARNING",
        })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 2,
            "validation": "l1_coverage",
            "passed": False,
            "coverage_percentage": coverage_pct,
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 2 validation FAILED - L1 coverage incomplete",
            "options": [
                "[1] FIX - Analyze missing entry points",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 2,
        "validation": "l1_coverage",
        "passed": True,
        "coverage_percentage": coverage_pct,
        "total_analyzed": l1_coverage.get("analyzed", l1_coverage.get("total_entry_points", 0)),
        "warnings": warnings,
        "message": "Phase 2 validation PASSED - 100% L1 coverage achieved",
    }


def validate_p3_trust_boundaries(project_root: str) -> Dict:
    """
    Validate Phase 3 trust boundary completeness.

    Validation Gates (from P3-TRUST-BOUNDARY.md):
    - BLOCKING: trust_boundaries block present with at least 1 boundary
    - BLOCKING: All boundaries have valid TB-xxx IDs
    - BLOCKING: Each boundary has type from [Network, Process, User, Data, Service]
    - WARNING: cross_boundary_flows should reference defined boundaries
    - WARNING: interfaces should have valid IF-xxx IDs
    """
    phase_data = load_phase_data(3, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 3,
            "message": "Phase 3 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", {})
    boundaries = blocks.get("trust_boundaries", {})
    interfaces = blocks.get("interfaces", {})
    data_nodes = blocks.get("data_nodes", {})
    cross_flows = blocks.get("cross_boundary_flows", {})

    if not boundaries:
        return {
            "status": "blocking",
            "phase": 3,
            "gate": "trust_boundaries",
            "message": "Missing trust_boundaries block",
            "action_required": "FIX",
        }

    blocking_issues = []
    warnings = []

    # Extract boundary list (handle both list and dict formats)
    boundary_list = boundaries if isinstance(boundaries, list) else boundaries.get("boundaries", [])
    if not boundary_list:
        return {
            "status": "blocking",
            "phase": 3,
            "gate": "boundary_count",
            "message": "No trust boundaries defined",
            "action_required": "FIX",
        }

    # Validate boundary IDs and types
    valid_types = ["Network", "Process", "User", "Data", "Service"]
    boundary_ids = []

    for boundary in boundary_list:
        if isinstance(boundary, dict):
            bid = boundary.get("id", "")
            boundary_ids.append(bid)

            # Check ID format
            if not ID_PATTERNS['trust_boundary'].match(bid):
                blocking_issues.append({
                    "type": "invalid_id",
                    "id": bid,
                    "issue": "Invalid trust boundary ID format",
                    "expected": "TB-xxx (e.g., TB-001)",
                    "severity": "BLOCKING",
                })

            # Check boundary type
            btype = boundary.get("type", "")
            if btype and btype not in valid_types:
                blocking_issues.append({
                    "type": "invalid_type",
                    "id": bid,
                    "issue": f"Invalid boundary type: {btype}",
                    "expected": valid_types,
                    "severity": "BLOCKING",
                })

    # Validate interfaces (WARNING level)
    interface_list = interfaces if isinstance(interfaces, list) else interfaces.get("interfaces", [])
    for iface in interface_list:
        if isinstance(iface, dict):
            iid = iface.get("id", "")
            if iid and not ID_PATTERNS['interface'].match(iid):
                warnings.append({
                    "type": "invalid_interface_id",
                    "id": iid,
                    "issue": "Invalid interface ID format",
                    "expected": "IF-xxx",
                    "severity": "WARNING",
                })

    # Validate data nodes (WARNING level)
    node_list = data_nodes if isinstance(data_nodes, list) else data_nodes.get("data_nodes", [])
    for node in node_list:
        if isinstance(node, dict):
            nid = node.get("id", "")
            if nid and not ID_PATTERNS['data_node'].match(nid):
                warnings.append({
                    "type": "invalid_data_node_id",
                    "id": nid,
                    "issue": "Invalid data node ID format",
                    "expected": "DN-xxx",
                    "severity": "WARNING",
                })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 3,
            "validation": "trust_boundaries",
            "passed": False,
            "boundary_count": len(boundary_list),
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 3 validation FAILED - trust boundary issues found",
            "options": [
                "[1] FIX - Correct trust boundary definitions",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 3,
        "validation": "trust_boundaries",
        "passed": True,
        "boundary_count": len(boundary_list),
        "boundary_ids": boundary_ids,
        "interface_count": len(interface_list),
        "data_node_count": len(node_list),
        "warnings": warnings,
        "message": f"Phase 3 validation PASSED - {len(boundary_list)} trust boundaries defined",
    }


def validate_p4_security_design(project_root: str) -> Dict:
    """
    Validate Phase 4 security design review completeness.

    Validation Gates (from P4-SECURITY-DESIGN-REVIEW.md):
    - BLOCKING: security_gaps block present
    - BLOCKING: All gaps have valid GAP-xxx IDs
    - BLOCKING: All gaps have domain from 16-domain list
    - WARNING: design_matrix should cover all 16 domains
    - WARNING: Each domain should have a rating
    """
    phase_data = load_phase_data(4, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 4,
            "message": "Phase 4 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", {})
    security_gaps = blocks.get("security_gaps", {})
    design_matrix = blocks.get("design_matrix", {})

    if not security_gaps:
        return {
            "status": "blocking",
            "phase": 4,
            "gate": "security_gaps",
            "message": "Missing security_gaps block",
            "action_required": "FIX",
        }

    blocking_issues = []
    warnings = []

    # Extract gaps list
    gaps_list = security_gaps if isinstance(security_gaps, list) else security_gaps.get("gaps", [])

    # Validate gap IDs and domains
    gap_ids = []
    gap_domains = set()

    for gap in gaps_list:
        if isinstance(gap, dict):
            gid = gap.get("id", "")
            gap_ids.append(gid)

            # Check ID format
            if gid and not ID_PATTERNS['security_gap'].match(gid):
                blocking_issues.append({
                    "type": "invalid_gap_id",
                    "id": gid,
                    "issue": "Invalid security gap ID format",
                    "expected": "GAP-xxx (e.g., GAP-001)",
                    "severity": "BLOCKING",
                })

            # Check domain
            domain = gap.get("domain", "")
            if domain:
                gap_domains.add(domain)
                if domain not in SECURITY_DOMAINS:
                    blocking_issues.append({
                        "type": "invalid_domain",
                        "id": gid,
                        "domain": domain,
                        "issue": f"Invalid security domain: {domain}",
                        "expected": SECURITY_DOMAINS,
                        "severity": "BLOCKING",
                    })

            # Check severity
            severity = gap.get("severity", "")
            if severity and severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                warnings.append({
                    "type": "invalid_severity",
                    "id": gid,
                    "issue": f"Non-standard severity: {severity}",
                    "expected": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "severity": "WARNING",
                })

    # Check design matrix coverage (WARNING)
    matrix_data = design_matrix if isinstance(design_matrix, dict) else {}
    assessed_domains = set()

    for domain in SECURITY_DOMAINS:
        domain_entry = matrix_data.get(domain, {})
        if domain_entry:
            assessed_domains.add(domain)
            rating = domain_entry.get("rating", domain_entry.get("status", ""))
            if not rating:
                warnings.append({
                    "type": "missing_rating",
                    "domain": domain,
                    "issue": f"Domain {domain} missing rating",
                    "severity": "WARNING",
                })

    missing_domains = set(SECURITY_DOMAINS) - assessed_domains
    if missing_domains and design_matrix:
        warnings.append({
            "type": "incomplete_matrix",
            "issue": f"Design matrix missing {len(missing_domains)} domains",
            "missing_domains": list(missing_domains),
            "severity": "WARNING",
        })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 4,
            "validation": "security_design",
            "passed": False,
            "gap_count": len(gaps_list),
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 4 validation FAILED - security gap issues found",
            "options": [
                "[1] FIX - Correct security gap definitions",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 4,
        "validation": "security_design",
        "passed": True,
        "gap_count": len(gaps_list),
        "gap_ids": gap_ids,
        "domains_covered": list(gap_domains),
        "matrix_coverage": f"{len(assessed_domains)}/{len(SECURITY_DOMAINS)}",
        "warnings": warnings,
        "message": f"Phase 4 validation PASSED - {len(gaps_list)} security gaps documented",
    }


def validate_p5_threat_inventory(project_root: str) -> Dict:
    """
    Validate Phase 5 threat inventory completeness.

    Validation Gates (from P5-STRIDE-ANALYSIS.md):
    - BLOCKING: threat_inventory block present
    - BLOCKING: All threats have valid T-{STRIDE}-{Element}-{Seq} IDs
    - BLOCKING: summary.total matches actual threat count
    - BLOCKING: by_stride totals sum to total
    - WARNING: All STRIDE categories should be represented
    """
    phase_data = load_phase_data(5, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 5,
            "message": "Phase 5 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", {})
    threat_inventory = blocks.get("threat_inventory", {})

    if not threat_inventory:
        return {
            "status": "blocking",
            "phase": 5,
            "gate": "threat_inventory",
            "message": "Missing threat_inventory block",
            "action_required": "FIX",
        }

    blocking_issues = []
    warnings = []

    # Extract threats list
    threats_list = threat_inventory.get("threats", [])
    summary = threat_inventory.get("summary", {})

    if not threats_list:
        return {
            "status": "blocking",
            "phase": 5,
            "gate": "threat_count",
            "message": "No threats defined in threat_inventory",
            "action_required": "FIX",
        }

    # Validate threat IDs
    threat_ids = []
    stride_counts = {'S': 0, 'T': 0, 'R': 0, 'I': 0, 'D': 0, 'E': 0}

    for threat in threats_list:
        if isinstance(threat, dict):
            tid = threat.get("id", "")
            threat_ids.append(tid)

            # Check ID format (support both formats)
            valid_format = (
                ID_PATTERNS['threat'].match(tid) or
                ID_PATTERNS['threat_alt'].match(tid)
            )
            if tid and not valid_format:
                blocking_issues.append({
                    "type": "invalid_threat_id",
                    "id": tid,
                    "issue": "Invalid threat ID format",
                    "expected": "T-{S|T|R|I|D|E}-{ElementID}-{Seq} (e.g., T-S-P-001-001)",
                    "severity": "BLOCKING",
                })

            # Count STRIDE category
            stride_type = threat.get("stride_type", "")
            if not stride_type and tid:
                # Extract from ID
                parts = tid.split('-')
                if len(parts) >= 2:
                    stride_type = parts[1]

            if stride_type in stride_counts:
                stride_counts[stride_type] += 1
            elif stride_type:
                warnings.append({
                    "type": "invalid_stride_type",
                    "id": tid,
                    "stride_type": stride_type,
                    "issue": f"Invalid STRIDE type: {stride_type}",
                    "expected": STRIDE_CATEGORIES,
                    "severity": "WARNING",
                })

    # Validate summary counts
    actual_count = len(threats_list)
    declared_total = summary.get("total", 0)

    if declared_total != actual_count:
        blocking_issues.append({
            "type": "count_mismatch",
            "issue": "Threat count mismatch",
            "declared": declared_total,
            "actual": actual_count,
            "severity": "BLOCKING",
        })

    # Validate by_stride totals
    by_stride = summary.get("by_stride", {})
    stride_total = sum(by_stride.get(s, 0) for s in STRIDE_CATEGORIES)

    if by_stride and stride_total != actual_count:
        blocking_issues.append({
            "type": "stride_sum_mismatch",
            "issue": "by_stride sum doesn't match total",
            "stride_sum": stride_total,
            "actual": actual_count,
            "severity": "BLOCKING",
        })

    # Check STRIDE coverage (WARNING)
    missing_stride = [s for s in STRIDE_CATEGORIES if stride_counts[s] == 0]
    if missing_stride:
        warnings.append({
            "type": "incomplete_stride_coverage",
            "issue": f"Missing STRIDE categories: {missing_stride}",
            "stride_counts": stride_counts,
            "severity": "WARNING",
        })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 5,
            "validation": "threat_inventory",
            "passed": False,
            "threat_count": actual_count,
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 5 validation FAILED - threat inventory issues found",
            "options": [
                "[1] FIX - Correct threat definitions",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 5,
        "validation": "threat_inventory",
        "passed": True,
        "threat_count": actual_count,
        "stride_distribution": stride_counts,
        "warnings": warnings,
        "message": f"Phase 5 validation PASSED - {actual_count} threats documented",
    }


def validate_p6_validated_risks(project_root: str) -> Dict:
    """
    Validate Phase 6 risk validation completeness.

    Validation Gates (from P6-RISK-VALIDATION.md):
    - BLOCKING: validated_risks block present
    - BLOCKING: All risks have valid VR-xxx IDs
    - BLOCKING: All VRs have threat_refs[] (CP2)
    - BLOCKING: Count conservation formula holds (CP1)
    - WARNING: POC-xxx required for Critical/High priority
    - WARNING: attack_chains should be defined
    """
    phase_data = load_phase_data(6, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 6,
            "message": "Phase 6 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", {})
    validated_risks = blocks.get("validated_risks", {})
    poc_details = blocks.get("poc_details", {})
    attack_chains = blocks.get("attack_chains", {})

    if not validated_risks:
        return {
            "status": "blocking",
            "phase": 6,
            "gate": "validated_risks",
            "message": "Missing validated_risks block",
            "action_required": "FIX",
        }

    blocking_issues = []
    warnings = []

    # Extract risk list
    risk_summary = validated_risks.get("risk_summary", {})
    risk_details = validated_risks.get("risk_details", [])

    if not risk_details:
        risk_details = validated_risks.get("risks", [])

    # Validate risk IDs and threat_refs
    vr_ids = []
    all_threat_refs = []
    critical_high_without_poc = []

    for risk in risk_details:
        if isinstance(risk, dict):
            vr_id = risk.get("id", "")
            vr_ids.append(vr_id)

            # Check VR ID format
            if vr_id and not ID_PATTERNS['validated_risk'].match(vr_id):
                blocking_issues.append({
                    "type": "invalid_vr_id",
                    "id": vr_id,
                    "issue": "Invalid validated risk ID format",
                    "expected": "VR-xxx (e.g., VR-001)",
                    "severity": "BLOCKING",
                })

            # Check threat_refs (CP2)
            threat_refs = risk.get("threat_refs", [])
            if not threat_refs:
                blocking_issues.append({
                    "type": "missing_threat_refs",
                    "id": vr_id,
                    "issue": "VR missing threat_refs[]",
                    "severity": "BLOCKING",
                })
            else:
                all_threat_refs.extend(threat_refs)

            # Check POC for Critical/High
            priority = risk.get("priority", "")
            poc_ref = risk.get("related_poc", risk.get("poc_id", ""))
            if priority in ["P0", "P1", "CRITICAL", "HIGH"] and not poc_ref:
                critical_high_without_poc.append(vr_id)

    # Check for forbidden RISK-xxx format
    risk_pattern = ID_PATTERNS['forbidden_risk']
    for risk in risk_details:
        if isinstance(risk, dict):
            for key, value in risk.items():
                if isinstance(value, str) and risk_pattern.match(value):
                    blocking_issues.append({
                        "type": "forbidden_id_format",
                        "id": value,
                        "issue": "Forbidden RISK-xxx format found (should be VR-xxx)",
                        "severity": "BLOCKING",
                    })

    # Count conservation check (basic)
    declared_counts = risk_summary.get("total_verified", 0) + \
                     risk_summary.get("total_theoretical", 0) + \
                     risk_summary.get("total_pending", 0) + \
                     risk_summary.get("total_excluded", 0)
    declared_identified = risk_summary.get("total_identified", 0)

    if declared_counts > 0 and declared_identified > 0 and declared_counts != declared_identified:
        warnings.append({
            "type": "count_conservation_warning",
            "issue": "Risk summary counts may not balance",
            "identified": declared_identified,
            "sum": declared_counts,
            "hint": "Run --validate-checkpoints for full CP1 validation",
            "severity": "WARNING",
        })

    # POC coverage warning
    if critical_high_without_poc:
        warnings.append({
            "type": "missing_poc",
            "issue": f"{len(critical_high_without_poc)} Critical/High risks without POC",
            "risks": critical_high_without_poc[:5],
            "severity": "WARNING",
        })

    # Attack chains warning
    chains_list = attack_chains if isinstance(attack_chains, list) else attack_chains.get("chains", [])
    if not chains_list:
        warnings.append({
            "type": "missing_attack_chains",
            "issue": "No attack chains defined",
            "severity": "WARNING",
        })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 6,
            "validation": "validated_risks",
            "passed": False,
            "risk_count": len(risk_details),
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 6 validation FAILED - validated risk issues found",
            "options": [
                "[1] FIX - Correct risk definitions",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 6,
        "validation": "validated_risks",
        "passed": True,
        "risk_count": len(risk_details),
        "vr_ids": vr_ids,
        "threat_ref_count": len(set(all_threat_refs)),
        "warnings": warnings,
        "message": f"Phase 6 validation PASSED - {len(risk_details)} validated risks documented",
    }


def validate_p7_mitigation_plan(project_root: str) -> Dict:
    """
    Validate Phase 7 mitigation plan completeness.

    Validation Gates (from P7-MITIGATION-PLANNING.md):
    - BLOCKING: mitigation_plan block present
    - BLOCKING: All mitigations have valid MIT-xxx IDs
    - BLOCKING: All mitigations have risk_refs[] linking to VR-xxx
    - WARNING: Every VR-xxx should have at least one MIT-xxx
    - WARNING: roadmap should be defined with timeline
    """
    phase_data = load_phase_data(7, project_root)

    if not phase_data:
        return {
            "status": "error",
            "phase": 7,
            "message": "Phase 7 data not found. Run --extract first.",
        }

    blocks = phase_data.get("blocks", {})
    mitigation_plan = blocks.get("mitigation_plan", {})
    roadmap = blocks.get("roadmap", {})

    if not mitigation_plan:
        return {
            "status": "blocking",
            "phase": 7,
            "gate": "mitigation_plan",
            "message": "Missing mitigation_plan block",
            "action_required": "FIX",
        }

    blocking_issues = []
    warnings = []

    # Extract mitigations list
    mitigations = mitigation_plan.get("mitigations", [])

    if not mitigations:
        return {
            "status": "blocking",
            "phase": 7,
            "gate": "mitigation_count",
            "message": "No mitigations defined in mitigation_plan",
            "action_required": "FIX",
        }

    # Validate mitigation IDs and risk_refs
    mit_ids = []
    covered_vrs = set()
    mitigations_without_risk_refs = []

    for mitigation in mitigations:
        if isinstance(mitigation, dict):
            mit_id = mitigation.get("id", "")
            mit_ids.append(mit_id)

            # Check MIT ID format
            if mit_id and not ID_PATTERNS['mitigation'].match(mit_id):
                blocking_issues.append({
                    "type": "invalid_mit_id",
                    "id": mit_id,
                    "issue": "Invalid mitigation ID format",
                    "expected": "MIT-xxx (e.g., MIT-001)",
                    "severity": "BLOCKING",
                })

            # Check for forbidden M-xxx format (collision with Module)
            if mit_id and ID_PATTERNS['forbidden_mitigation'].match(mit_id):
                blocking_issues.append({
                    "type": "forbidden_mit_format",
                    "id": mit_id,
                    "issue": "M-xxx format collides with Module ID",
                    "expected": "MIT-xxx (e.g., MIT-001)",
                    "severity": "BLOCKING",
                })

            # Check risk_refs
            risk_refs = mitigation.get("risk_refs", [])
            if not risk_refs:
                mitigations_without_risk_refs.append(mit_id)
            else:
                for vr in risk_refs:
                    covered_vrs.add(vr)

            # Validate risk_refs format
            for vr in risk_refs:
                if not ID_PATTERNS['validated_risk'].match(vr):
                    warnings.append({
                        "type": "invalid_risk_ref",
                        "mitigation": mit_id,
                        "risk_ref": vr,
                        "issue": "Invalid risk reference format",
                        "expected": "VR-xxx",
                        "severity": "WARNING",
                    })

    # Mitigations without risk_refs is blocking
    if mitigations_without_risk_refs:
        blocking_issues.append({
            "type": "missing_risk_refs",
            "mitigations": mitigations_without_risk_refs,
            "issue": f"{len(mitigations_without_risk_refs)} mitigations missing risk_refs[]",
            "severity": "BLOCKING",
        })

    # Cross-validate with P6 VRs (try to load P6 for comparison)
    p6_data = load_phase_data(6, project_root)
    if p6_data:
        p6_blocks = p6_data.get("blocks", {})
        p6_risks = p6_blocks.get("validated_risks", {})
        risk_details = p6_risks.get("risk_details", p6_risks.get("risks", []))

        p6_vr_ids = set()
        for risk in risk_details:
            if isinstance(risk, dict):
                vr_id = risk.get("id", "")
                if vr_id:
                    p6_vr_ids.add(vr_id)

        uncovered_vrs = p6_vr_ids - covered_vrs
        if uncovered_vrs:
            warnings.append({
                "type": "uncovered_risks",
                "issue": f"{len(uncovered_vrs)} VRs without mitigation",
                "uncovered": list(uncovered_vrs)[:5],
                "severity": "WARNING",
            })

    # Roadmap validation (WARNING)
    roadmap_data = roadmap if roadmap else mitigation_plan.get("roadmap", {})
    if not roadmap_data:
        warnings.append({
            "type": "missing_roadmap",
            "issue": "No roadmap defined",
            "severity": "WARNING",
        })
    else:
        # Check roadmap has timeline sections
        expected_sections = ["immediate", "short_term", "medium_term", "long_term"]
        present_sections = [s for s in expected_sections if roadmap_data.get(s)]
        if len(present_sections) < 2:
            warnings.append({
                "type": "incomplete_roadmap",
                "issue": f"Roadmap only has {len(present_sections)} timeline sections",
                "present": present_sections,
                "expected": expected_sections,
                "severity": "WARNING",
            })

    # Determine overall status
    if blocking_issues:
        return {
            "status": "blocking",
            "phase": 7,
            "validation": "mitigation_plan",
            "passed": False,
            "mitigation_count": len(mitigations),
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "message": "Phase 7 validation FAILED - mitigation plan issues found",
            "options": [
                "[1] FIX - Correct mitigation definitions",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 7,
        "validation": "mitigation_plan",
        "passed": True,
        "mitigation_count": len(mitigations),
        "mit_ids": mit_ids,
        "vr_coverage": len(covered_vrs),
        "warnings": warnings,
        "message": f"Phase 7 validation PASSED - {len(mitigations)} mitigations documented",
    }


def validate_phase(phase: int, project_root: str) -> Dict:
    """
    Route to appropriate phase-specific validation function.

    Args:
        phase: Phase number (1-8)
        project_root: Project root directory

    Returns:
        Dict with validation results including:
        - status: "passed", "blocking", "warning", or "error"
        - phase: Phase number
        - passed: Boolean
        - blocking_issues: List of blocking issues (if any)
        - warnings: List of warnings (if any)
        - message: Human-readable summary
    """
    # Phase-specific validators
    validators = {
        1: validate_p1_checklist,
        2: validate_p2_l1_coverage,
        3: validate_p3_trust_boundaries,
        4: validate_p4_security_design,
        5: validate_p5_threat_inventory,
        6: validate_p6_validated_risks,
        7: validate_p7_mitigation_plan,
    }

    if phase in validators:
        return validators[phase](project_root)

    # Phase 8 uses generic validation (reports, not data blocks)
    if phase == 8:
        return _validate_p8_reports(project_root)

    # Unknown phase
    return {
        "status": "error",
        "phase": phase,
        "message": f"Unknown phase: {phase}. Valid phases are 1-8.",
    }


def _validate_p8_reports(project_root: str) -> Dict:
    """
    Validate Phase 8 report generation completeness.

    Checks that all 8 required reports are generated in Risk_Assessment_Report/.
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    if not report_dir.exists():
        return {
            "status": "blocking",
            "phase": 8,
            "gate": "report_directory",
            "message": "Risk_Assessment_Report/ directory not found",
            "action_required": "FIX",
        }

    required_reports = [
        "RISK-ASSESSMENT-REPORT",
        "RISK-INVENTORY",
        "MITIGATION-MEASURES",
        "PENETRATION-TEST-PLAN",
        "ARCHITECTURE-ANALYSIS",
        "DFD-DIAGRAM",
        "COMPLIANCE-REPORT",
        "ATTACK-PATH-VALIDATION",
    ]

    found_reports = []
    missing_reports = []

    for report_name in required_reports:
        found = False
        for f in report_dir.glob("**/*.md"):
            if report_name.upper() in f.name.upper():
                found = True
                found_reports.append(f.name)
                break
        if not found:
            missing_reports.append(report_name)

    if missing_reports:
        return {
            "status": "blocking",
            "phase": 8,
            "validation": "reports",
            "passed": False,
            "found_reports": found_reports,
            "missing_reports": missing_reports,
            "message": f"Phase 8 validation FAILED - {len(missing_reports)} reports missing",
            "options": [
                "[1] FIX - Generate missing reports",
                "[2] ACCEPT - Acknowledge limitations and continue",
                "[3] ABORT - Terminate session",
            ],
        }

    return {
        "status": "passed",
        "phase": 8,
        "validation": "reports",
        "passed": True,
        "found_reports": found_reports,
        "message": f"Phase 8 validation PASSED - all {len(required_reports)} reports generated",
    }


# ============================================================================
# Aggregation Functions
# ============================================================================

def aggregate_phases(
    phases: List[int],
    project_root: str,
    format_type: str = "summary"
) -> Dict:
    """
    Aggregate data from multiple phases.

    Args:
        phases: List of phase numbers to aggregate
        project_root: Project root directory
        format_type: "summary" or "full"

    Returns:
        Aggregated data
    """
    result = {
        "phases_requested": phases,
        "phases_found": [],
        "phases_missing": [],
        "aggregated_data": {},
    }

    for phase in phases:
        phase_data = load_phase_data(phase, project_root)

        if phase_data:
            result["phases_found"].append(phase)

            if format_type == "summary":
                # Summary: block names and counts only
                blocks = phase_data.get("blocks", {})
                result["aggregated_data"][f"phase{phase}"] = {
                    "extracted_at": phase_data.get("extracted_at"),
                    "blocks": {
                        name: _count_items(data)
                        for name, data in blocks.items()
                    },
                }
            else:
                # Full: include all data
                result["aggregated_data"][f"phase{phase}"] = phase_data
        else:
            result["phases_missing"].append(phase)

    result["complete"] = len(result["phases_missing"]) == 0

    return result


# ============================================================================
# Count Conservation Validation (CP1/CP2/CP3)
# Migrated from validate_count_conservation.py v2.1.0
# ============================================================================

# Regex patterns for content parsing (from validate_count_conservation.py)
_THREAT_PATTERN = re.compile(r'T-[STRIDE]-[A-Z]+\d+-\d{3}')
_VR_PATTERN = re.compile(r'VR-\d{3}')
_TOTAL_PATTERN = re.compile(r'(?:total|总数|总计)[\s:]*(\d+)', re.IGNORECASE)
_THREAT_REF_PATTERN = re.compile(r'threat_refs?\s*[:\|]\s*\[?([^\]\n]+)\]?', re.IGNORECASE)


def extract_threat_ids_from_phase_data(phase5_data: Dict) -> Tuple[int, List[str]]:
    """
    Extract threat IDs from phase 5 structured data.

    Args:
        phase5_data: Phase 5 data loaded via load_phase_data()

    Returns:
        Tuple of (declared_total, list_of_threat_ids)
    """
    if not phase5_data:
        return 0, []

    blocks = phase5_data.get("blocks", {})
    threat_inventory = blocks.get("threat_inventory", {})

    threats = []

    # Handle different data structures
    if isinstance(threat_inventory, dict):
        # Check for 'threats' key
        threat_list = threat_inventory.get("threats", [])
        if isinstance(threat_list, list):
            for threat in threat_list:
                if isinstance(threat, dict):
                    threat_id = threat.get("id") or threat.get("threat_id")
                    if threat_id:
                        threats.append(threat_id)
        # Check for summary total
        summary = threat_inventory.get("summary", {})
        declared_total = summary.get("total", len(threats))
    elif isinstance(threat_inventory, list):
        # Direct list of threats
        for threat in threat_inventory:
            if isinstance(threat, dict):
                threat_id = threat.get("id") or threat.get("threat_id")
                if threat_id:
                    threats.append(threat_id)
        declared_total = len(threats)
    else:
        declared_total = 0

    # Deduplicate
    threats = list(set(threats))

    return declared_total, threats


def extract_vr_mapping_from_phase_data(phase6_data: Dict) -> Dict[str, List[str]]:
    """
    Extract VR to threat_refs mapping from phase 6 data.

    Args:
        phase6_data: Phase 6 data loaded via load_phase_data()

    Returns:
        Dict mapping VR IDs to their threat_refs (e.g., {'VR-001': ['T-S-P1-001', ...]})
    """
    if not phase6_data:
        return {}

    blocks = phase6_data.get("blocks", {})
    validated_risks = blocks.get("validated_risks", {})

    vr_mapping = {}

    # Handle different data structures
    if isinstance(validated_risks, dict):
        risk_list = validated_risks.get("risks", [])
    elif isinstance(validated_risks, list):
        risk_list = validated_risks
    else:
        risk_list = []

    for risk in risk_list:
        if isinstance(risk, dict):
            vr_id = risk.get("id") or risk.get("vr_id")
            if vr_id:
                # Get threat_refs (can be 'threat_refs', 'threat_ref', or 'source_threats')
                refs = risk.get("threat_refs") or risk.get("threat_ref") or risk.get("source_threats", [])
                if isinstance(refs, str):
                    refs = [refs]
                elif not isinstance(refs, list):
                    refs = []
                vr_mapping[vr_id] = list(set(refs))

    return vr_mapping


def extract_excluded_from_phase_data(phase6_data: Dict) -> List[str]:
    """
    Extract excluded threat IDs from phase 6 data.

    Args:
        phase6_data: Phase 6 data loaded via load_phase_data()

    Returns:
        List of excluded threat IDs
    """
    if not phase6_data:
        return []

    blocks = phase6_data.get("blocks", {})

    excluded = []

    # Check in validated_risks block for excluded section
    validated_risks = blocks.get("validated_risks", {})
    if isinstance(validated_risks, dict):
        excluded_threats = validated_risks.get("excluded_threats", [])
        if isinstance(excluded_threats, list):
            for threat in excluded_threats:
                if isinstance(threat, str):
                    excluded.append(threat)
                elif isinstance(threat, dict):
                    threat_id = threat.get("id") or threat.get("threat_id")
                    if threat_id:
                        excluded.append(threat_id)

        # Also check for threat_disposition block
        threat_disposition = validated_risks.get("threat_disposition", {})
        if isinstance(threat_disposition, dict):
            excluded_list = threat_disposition.get("excluded", [])
            if isinstance(excluded_list, list):
                for threat in excluded_list:
                    if isinstance(threat, str):
                        excluded.append(threat)
                    elif isinstance(threat, dict):
                        threat_id = threat.get("id") or threat.get("threat_id")
                        if threat_id:
                            excluded.append(threat_id)

    return list(set(excluded))


def extract_vr_ids_from_phase_data(phase6_data: Dict) -> List[str]:
    """
    Extract all unique VR IDs from phase 6 data.

    Args:
        phase6_data: Phase 6 data loaded via load_phase_data()

    Returns:
        Sorted list of unique VR IDs
    """
    vr_mapping = extract_vr_mapping_from_phase_data(phase6_data)
    return sorted(list(vr_mapping.keys()))


# ============================================================================
# Markdown Parsing Functions (backward compatibility with validate_count_conservation.py)
# ============================================================================

def extract_threat_ids_from_markdown(content: str) -> Tuple[int, List[str]]:
    """
    Extract threat IDs from P5 markdown content (backward compatibility).

    This function replicates the regex-based parsing from validate_count_conservation.py
    for direct markdown file analysis without phase_data extraction.

    Args:
        content: Raw markdown content of P5-STRIDE-THREATS.md

    Returns:
        Tuple of (declared_total, list_of_threat_ids)
    """
    threats = []

    # Look for threat IDs in format T-X-XXX-NNN
    matches = _THREAT_PATTERN.findall(content)
    threats = list(set(matches))  # Unique threats

    # Try to find total count from summary section
    total_match = _TOTAL_PATTERN.search(content)

    if total_match:
        declared_total = int(total_match.group(1))
    else:
        declared_total = len(threats)

    return declared_total, threats


def extract_vr_mapping_from_markdown(content: str) -> Dict[str, List[str]]:
    """
    Extract VR mapping from P6 markdown content (backward compatibility).

    This function replicates the regex-based parsing from validate_count_conservation.py.

    Args:
        content: Raw markdown content of P6-RISK-VALIDATION.md

    Returns:
        Dict mapping VR IDs to their threat_refs
    """
    vr_mapping = {}

    # Split by VR entries and extract refs
    lines = content.split('\n')
    current_vr = None

    for line in lines:
        vr_match = _VR_PATTERN.search(line)
        if vr_match:
            current_vr = vr_match.group()
            if current_vr not in vr_mapping:
                vr_mapping[current_vr] = []

        ref_match = _THREAT_REF_PATTERN.search(line)
        if ref_match and current_vr:
            refs = ref_match.group(1)
            # Parse comma-separated threat IDs
            threat_ids = _THREAT_PATTERN.findall(refs)
            vr_mapping[current_vr].extend(threat_ids)

    # Deduplicate
    for vr_id in vr_mapping:
        vr_mapping[vr_id] = list(set(vr_mapping[vr_id]))

    return vr_mapping


def extract_excluded_from_markdown(content: str) -> List[str]:
    """
    Extract excluded threats from P6 markdown content (backward compatibility).

    Args:
        content: Raw markdown content of P6-RISK-VALIDATION.md

    Returns:
        List of excluded threat IDs
    """
    excluded = []

    # Look for excluded section - stop at:
    # - ## or higher level heading
    # - ``` code block start
    # - End of file
    excluded_section = re.search(
        r'##[^\n]*[Ee]xcluded[^\n]*\n(.*?)(?=\n#{2,}|\n```|\Z)',
        content,
        re.DOTALL
    )

    if excluded_section:
        section_content = excluded_section.group(1)
        threat_ids = _THREAT_PATTERN.findall(section_content)
        excluded = list(set(threat_ids))

    # Also check for inline "excluded_threats:" list (not under a heading)
    if not excluded:
        inline_section = re.search(
            r'excluded_threats?\s*:\s*\n((?:[-*]\s*T-[STRIDE]-[^\n]+\n?)+)',
            content,
            re.IGNORECASE
        )
        if inline_section:
            threat_ids = _THREAT_PATTERN.findall(inline_section.group(1))
            excluded = list(set(threat_ids))

    return excluded


def extract_vr_ids_from_markdown(content: str) -> List[str]:
    """
    Extract all unique VR IDs from P6 markdown content (backward compatibility).

    Args:
        content: Raw markdown content of P6-RISK-VALIDATION.md

    Returns:
        Sorted list of unique VR IDs
    """
    matches = _VR_PATTERN.findall(content)
    return sorted(list(set(matches)))


# ============================================================================
# Main Checkpoint Validation Functions
# ============================================================================

def validate_cp1_threat_conservation(project_root: str, markdown_mode: bool = False) -> Dict:
    """
    CP1: Validate P5 → P6 threat count conservation.

    Formula: consolidated + excluded = p5_total

    Args:
        project_root: Project root directory
        markdown_mode: If True, parse from raw Markdown files instead of phase_data

    Returns:
        Dict with checkpoint, status (PASS/FAIL/WARN), details, message
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    if markdown_mode:
        # Find and read markdown files directly
        p5_file = None
        p6_file = None

        for f in report_dir.glob('**/*.md'):
            name = f.name.upper()
            if 'P5' in name or 'STRIDE-THREAT' in name:
                p5_file = f
            elif 'P6' in name or 'RISK-VALIDATION' in name:
                p6_file = f

        if not p5_file:
            return {
                "checkpoint": "CP1",
                "status": "WARN",
                "message": "P5 markdown file not found",
                "details": {"report_dir": str(report_dir)},
            }

        if not p6_file:
            return {
                "checkpoint": "CP1",
                "status": "WARN",
                "message": "P6 markdown file not found",
                "details": {"report_dir": str(report_dir)},
            }

        p5_content = p5_file.read_text(encoding='utf-8')
        p6_content = p6_file.read_text(encoding='utf-8')

        p5_total, p5_threats = extract_threat_ids_from_markdown(p5_content)
        vr_mapping = extract_vr_mapping_from_markdown(p6_content)
        excluded = extract_excluded_from_markdown(p6_content)

    else:
        # Use phase_data
        p5_data = load_phase_data(5, project_root)
        p6_data = load_phase_data(6, project_root)

        if not p5_data:
            return {
                "checkpoint": "CP1",
                "status": "WARN",
                "message": "Phase 5 data not found. Run --extract on P5 markdown first.",
                "details": {"hint": "python phase_data.py --extract P5-STRIDE-THREATS.md --phase 5"},
            }

        if not p6_data:
            return {
                "checkpoint": "CP1",
                "status": "WARN",
                "message": "Phase 6 data not found. Run --extract on P6 markdown first.",
                "details": {"hint": "python phase_data.py --extract P6-RISK-VALIDATION.md --phase 6"},
            }

        p5_total, p5_threats = extract_threat_ids_from_phase_data(p5_data)
        vr_mapping = extract_vr_mapping_from_phase_data(p6_data)
        excluded = extract_excluded_from_phase_data(p6_data)

    # Consolidate all threat_refs from VRs
    consolidated = []
    for refs in vr_mapping.values():
        consolidated.extend(refs)
    consolidated = list(set(consolidated))

    # Calculate
    consolidated_count = len(consolidated)
    excluded_count = len(excluded)
    total_accounted = consolidated_count + excluded_count

    details = {
        "p5_total": p5_total,
        "consolidated": consolidated_count,
        "excluded": excluded_count,
        "accounted": total_accounted,
        "formula": f"{consolidated_count} + {excluded_count} = {total_accounted}",
    }

    # Determine status
    if total_accounted == p5_total:
        return {
            "checkpoint": "CP1",
            "status": "PASS",
            "message": f"Count conservation verified: {consolidated_count} + {excluded_count} = {p5_total}",
            "details": details,
        }
    elif total_accounted < p5_total:
        missing = p5_total - total_accounted
        return {
            "checkpoint": "CP1",
            "status": "FAIL",
            "message": f"Missing {missing} threats! Expected {p5_total}, got {total_accounted}",
            "details": details,
        }
    else:
        excess = total_accounted - p5_total
        return {
            "checkpoint": "CP1",
            "status": "WARN",
            "message": f"Excess {excess} threats counted. Expected {p5_total}, got {total_accounted}",
            "details": details,
        }


def validate_cp2_vr_threat_refs(project_root: str, markdown_mode: bool = False) -> Dict:
    """
    CP2: Validate every VR has at least one threat_ref.

    Args:
        project_root: Project root directory
        markdown_mode: If True, parse from raw Markdown files

    Returns:
        Dict with checkpoint, status (PASS/FAIL/WARN), details, message
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    if markdown_mode:
        p6_file = None
        for f in report_dir.glob('**/*.md'):
            name = f.name.upper()
            if 'P6' in name or 'RISK-VALIDATION' in name:
                p6_file = f
                break

        if not p6_file:
            return {
                "checkpoint": "CP2",
                "status": "WARN",
                "message": "P6 markdown file not found",
                "details": {"report_dir": str(report_dir)},
            }

        p6_content = p6_file.read_text(encoding='utf-8')
        vr_mapping = extract_vr_mapping_from_markdown(p6_content)
    else:
        p6_data = load_phase_data(6, project_root)

        if not p6_data:
            return {
                "checkpoint": "CP2",
                "status": "WARN",
                "message": "Phase 6 data not found. Run --extract on P6 markdown first.",
                "details": {"hint": "python phase_data.py --extract P6-RISK-VALIDATION.md --phase 6"},
            }

        vr_mapping = extract_vr_mapping_from_phase_data(p6_data)

    # Find VRs without threat_refs
    empty_vrs = [vr for vr, refs in vr_mapping.items() if not refs]

    if not vr_mapping:
        return {
            "checkpoint": "CP2",
            "status": "WARN",
            "message": "No ValidatedRisk entries found",
            "details": {"vr_count": 0},
        }

    if empty_vrs:
        return {
            "checkpoint": "CP2",
            "status": "FAIL",
            "message": f"{len(empty_vrs)} VRs missing threat_refs: {empty_vrs}",
            "details": {"empty_vrs": empty_vrs, "total_vrs": len(vr_mapping)},
        }

    return {
        "checkpoint": "CP2",
        "status": "PASS",
        "message": f"All {len(vr_mapping)} VRs have threat_refs",
        "details": {"vr_count": len(vr_mapping)},
    }


def validate_cp3_report_conservation(project_root: str) -> Dict:
    """
    CP3: Validate P6 VR count equals each report's VR count.

    Args:
        project_root: Project root directory

    Returns:
        Dict with checkpoint, status (PASS/FAIL/WARN), details, message
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    # Get P6 VR IDs (try phase_data first, then markdown)
    p6_data = load_phase_data(6, project_root)

    if p6_data:
        p6_vr_ids = extract_vr_ids_from_phase_data(p6_data)
    else:
        # Fallback to markdown
        p6_file = None
        for f in report_dir.glob('**/*.md'):
            name = f.name.upper()
            if 'P6' in name or 'RISK-VALIDATION' in name:
                p6_file = f
                break

        if not p6_file:
            return {
                "checkpoint": "CP3",
                "status": "WARN",
                "message": "P6 data/file not found",
                "details": {"report_dir": str(report_dir)},
            }

        p6_content = p6_file.read_text(encoding='utf-8')
        p6_vr_ids = extract_vr_ids_from_markdown(p6_content)

    p6_vr_count = len(p6_vr_ids)

    # Extract VR counts from all four final reports
    report_counts = {}

    for report_name in FINAL_REPORTS:
        report_info = {
            'file': None,
            'vr_ids': [],
            'count': 0,
            'found': False
        }

        # Search for report file (case-insensitive, with project prefix)
        for f in report_dir.glob('**/*.md'):
            if report_name.upper() in f.name.upper():
                report_info['file'] = str(f)
                report_info['found'] = True
                try:
                    content = f.read_text(encoding='utf-8')
                    matches = _VR_PATTERN.findall(content)
                    report_info['vr_ids'] = sorted(list(set(matches)))
                    report_info['count'] = len(report_info['vr_ids'])
                except Exception as e:
                    report_info['error'] = str(e)
                break

        report_counts[report_name] = report_info

    # Analyze discrepancies
    discrepancies = []
    missing_reports = []

    for report_name, info in report_counts.items():
        if not info['found']:
            missing_reports.append(report_name)
            continue

        if info['count'] != p6_vr_count:
            # Find which VRs are missing or extra
            p6_set = set(p6_vr_ids)
            report_set = set(info['vr_ids'])
            missing_in_report = p6_set - report_set
            extra_in_report = report_set - p6_set

            discrepancies.append({
                'report': report_name,
                'expected': p6_vr_count,
                'actual': info['count'],
                'missing': list(missing_in_report)[:5] if missing_in_report else [],
                'extra': list(extra_in_report)[:5] if extra_in_report else []
            })

    details = {
        'p6_vr_count': p6_vr_count,
        'p6_vr_ids': p6_vr_ids[:10] if len(p6_vr_ids) > 10 else p6_vr_ids,
        'reports_checked': len(FINAL_REPORTS),
        'reports_found': len(FINAL_REPORTS) - len(missing_reports),
        'per_report_counts': {
            name: info['count'] for name, info in report_counts.items() if info['found']
        }
    }

    if missing_reports:
        details['missing_reports'] = missing_reports

    if discrepancies:
        details['discrepancies'] = discrepancies

    # Determine status
    if not p6_vr_ids:
        return {
            "checkpoint": "CP3",
            "status": "WARN",
            "message": "No VR IDs found in P6 - skipping CP3 validation",
            "details": details,
        }

    if missing_reports and len(missing_reports) == len(FINAL_REPORTS):
        return {
            "checkpoint": "CP3",
            "status": "WARN",
            "message": "No final reports found - skipping CP3 validation",
            "details": details,
        }

    if discrepancies:
        mismatch_reports = [d['report'] for d in discrepancies]
        return {
            "checkpoint": "CP3",
            "status": "FAIL",
            "message": f"CP3 FAIL: VR count mismatch in {mismatch_reports}. P6 has {p6_vr_count} VRs.",
            "details": details,
        }

    if missing_reports:
        return {
            "checkpoint": "CP3",
            "status": "WARN",
            "message": f"CP3 PARTIAL: {len(FINAL_REPORTS) - len(missing_reports)} reports match, but missing: {missing_reports}",
            "details": details,
        }

    return {
        "checkpoint": "CP3",
        "status": "PASS",
        "message": f"CP3 PASS: All {len(FINAL_REPORTS)} reports have {p6_vr_count} VRs matching P6",
        "details": details,
    }


def validate_id_formats_in_phase(phase: int, project_root: str) -> Dict:
    """
    Validate ID formats in a specific phase.

    Checks:
    - Forbidden RISK-xxx (should be VR-xxx)
    - Non-compliant threat IDs

    Args:
        phase: Phase number (5 or 6 typically)
        project_root: Project root directory

    Returns:
        Dict with status (PASS/FAIL), details, and issues found
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    # Try to read markdown file for this phase
    phase_file = None
    for f in report_dir.glob('**/*.md'):
        name = f.name.upper()
        if f'P{phase}' in name:
            phase_file = f
            break

    if not phase_file:
        return {
            "validation": "id_formats",
            "phase": phase,
            "status": "WARN",
            "message": f"Phase {phase} markdown file not found",
        }

    content = phase_file.read_text(encoding='utf-8')

    issues = []

    # Check for RISK-xxx (should be VR-xxx)
    risk_ids = re.findall(r'\bRISK-\d+\b', content)
    if risk_ids:
        issues.append({
            "type": "forbidden_risk_id",
            "message": f"Found forbidden RISK-xxx IDs: {list(set(risk_ids))[:5]}",
            "count": len(set(risk_ids)),
            "hint": "Use VR-xxx format instead of RISK-xxx",
        })

    # Check for T-X-CATEGORY-xxx (should keep ElementID)
    bad_threat_ids = re.findall(r'\bT-[STRIDE]-[A-Z]{3,}-\d{3}\b', content)
    # Filter out valid ElementID patterns (which have digits in ElementID)
    truly_bad = [t for t in bad_threat_ids if not re.match(r'T-[STRIDE]-[A-Z]+\d+-\d{3}', t)]
    if truly_bad:
        issues.append({
            "type": "non_compliant_threat_id",
            "message": f"Found non-compliant threat IDs: {list(set(truly_bad))[:5]}",
            "count": len(set(truly_bad)),
            "hint": "Threat IDs should be T-X-ElementID-NNN (e.g., T-S-P1-001)",
        })

    if issues:
        return {
            "validation": "id_formats",
            "phase": phase,
            "status": "FAIL",
            "message": " | ".join([i["message"] for i in issues]),
            "details": {"issues": issues},
        }

    return {
        "validation": "id_formats",
        "phase": phase,
        "status": "PASS",
        "message": "All ID formats compliant",
        "details": {"file_checked": str(phase_file)},
    }


def validate_all_checkpoints(project_root: str, markdown_mode: bool = False) -> Dict:
    """
    Execute all checkpoint validations (CP1 + CP2 + CP3).

    Args:
        project_root: Project root directory
        markdown_mode: If True, use markdown parsing mode for CP1/CP2

    Returns:
        Dict with overall_status, individual checkpoint results, summary
    """
    results = {
        "validation": "all_checkpoints",
        "checkpoints": {},
        "blocking_failures": 0,
        "warnings": 0,
    }

    # Run all checkpoints
    cp1_result = validate_cp1_threat_conservation(project_root, markdown_mode)
    cp2_result = validate_cp2_vr_threat_refs(project_root, markdown_mode)
    cp3_result = validate_cp3_report_conservation(project_root)

    results["checkpoints"]["cp1"] = cp1_result
    results["checkpoints"]["cp2"] = cp2_result
    results["checkpoints"]["cp3"] = cp3_result

    # Count failures and warnings
    for cp_result in [cp1_result, cp2_result, cp3_result]:
        if cp_result["status"] == "FAIL":
            results["blocking_failures"] += 1
        elif cp_result["status"] == "WARN":
            results["warnings"] += 1

    # Determine overall status
    if results["blocking_failures"] > 0:
        results["overall_status"] = "FAIL"
        results["message"] = f"{results['blocking_failures']} checkpoint(s) failed"
    elif results["warnings"] > 0:
        results["overall_status"] = "WARN"
        results["message"] = f"All checkpoints passed with {results['warnings']} warning(s)"
    else:
        results["overall_status"] = "PASS"
        results["message"] = "All checkpoints passed"

    results["checked_at"] = datetime.now().isoformat()

    return results


def validate_workflow_complete(project_root: str) -> Dict:
    """
    Validate complete workflow data integrity.

    Checks:
    1. All phases are extracted
    2. Phase-specific validations pass (P1 checklist, P2 L1 coverage)
    3. All checkpoints pass (CP1, CP2, CP3)
    4. ID formats are compliant
    5. Ready for report generation

    Args:
        project_root: Project root directory

    Returns:
        Dict with overall workflow validation status
    """
    results = {
        "validation": "workflow",
        "phases": {},
        "phase_validations": {},
        "checkpoints": {},
        "id_validations": {},
        "blockers": [],
        "warnings": [],
    }

    # Check phase extraction status
    for phase in range(1, 9):
        phase_data = load_phase_data(phase, project_root)
        results["phases"][phase] = {
            "extracted": phase_data is not None,
            "has_blocks": bool(phase_data.get("blocks")) if phase_data else False,
        }

        if not phase_data and phase <= 7:  # P8 is report generation
            results["blockers"].append(f"Phase {phase} data not extracted")

    # Phase-specific validations
    if results["phases"].get(1, {}).get("extracted"):
        p1_val = validate_p1_checklist(project_root)
        results["phase_validations"]["p1_checklist"] = p1_val.get("status", "error")
        if p1_val.get("status") == "blocking":
            results["blockers"].append("P1 checklist validation failed")

    if results["phases"].get(2, {}).get("extracted"):
        p2_val = validate_p2_l1_coverage(project_root)
        results["phase_validations"]["p2_l1_coverage"] = p2_val.get("status", "error")
        if p2_val.get("status") == "blocking":
            results["blockers"].append("P2 L1 coverage validation failed")

    # Checkpoint validations
    if results["phases"].get(5, {}).get("extracted") and results["phases"].get(6, {}).get("extracted"):
        cp1 = validate_cp1_threat_conservation(project_root)
        cp2 = validate_cp2_vr_threat_refs(project_root)
        cp3 = validate_cp3_report_conservation(project_root)

        results["checkpoints"] = {
            "cp1": cp1["status"],
            "cp2": cp2["status"],
            "cp3": cp3["status"],
        }

        if cp1["status"] == "FAIL":
            results["blockers"].append(f"CP1 failed: {cp1['message']}")
        if cp2["status"] == "FAIL":
            results["blockers"].append(f"CP2 failed: {cp2['message']}")
        if cp3["status"] == "FAIL":
            results["warnings"].append(f"CP3 failed: {cp3['message']}")  # CP3 is warning-level

    # ID format validations
    for phase in [5, 6]:
        if results["phases"].get(phase, {}).get("extracted"):
            id_val = validate_id_formats_in_phase(phase, project_root)
            results["id_validations"][f"phase{phase}"] = id_val["status"]
            if id_val["status"] == "FAIL":
                results["warnings"].append(f"Phase {phase} ID format issues: {id_val['message']}")

    # Determine overall status
    if results["blockers"]:
        results["overall_status"] = "BLOCKED"
        results["ready_for_report"] = False
        results["message"] = f"Workflow blocked: {len(results['blockers'])} issue(s)"
    elif results["warnings"]:
        results["overall_status"] = "READY_WITH_WARNINGS"
        results["ready_for_report"] = True
        results["message"] = f"Workflow ready with {len(results['warnings'])} warning(s)"
    else:
        results["overall_status"] = "READY"
        results["ready_for_report"] = True
        results["message"] = "Workflow validation PASSED - ready for Phase 8 report generation"

    results["checked_at"] = datetime.now().isoformat()

    return results


# ============================================================================
# Phase End Protocol
# ============================================================================

def _auto_detect_markdown_file(phase: int, project_root: str, session_id: Optional[str] = None) -> Optional[Path]:
    """
    Auto-detect the markdown file for a given phase.

    Search order:
    1. Session directory (if session_id provided or current session exists)
    2. Risk_Assessment_Report directory
    3. .phase_working directory (legacy)

    Args:
        phase: Phase number (1-8)
        project_root: Project root directory
        session_id: Optional session ID

    Returns:
        Path to markdown file, or None if not found
    """
    report_dir = Path(project_root) / "Risk_Assessment_Report"

    # Phase file patterns to search
    phase_patterns = [
        f"P{phase}-*.md",
        f"p{phase}-*.md",
    ]

    # Phase-specific name patterns
    phase_name_patterns = {
        1: ["PROJECT-UNDERSTANDING", "PROJECT_UNDERSTANDING"],
        2: ["DFD-ANALYSIS", "DFD_ANALYSIS", "CALL-FLOW", "DATA-FLOW"],
        3: ["TRUST-BOUNDARY", "TRUST_BOUNDARY"],
        4: ["SECURITY-DESIGN", "SECURITY_DESIGN", "DESIGN-REVIEW"],
        5: ["STRIDE-THREATS", "STRIDE_THREATS", "STRIDE-ANALYSIS"],
        6: ["RISK-VALIDATION", "RISK_VALIDATION", "VALIDATED-RISKS"],
        7: ["MITIGATION", "MITIGATION-PLAN", "MITIGATION_PLAN"],
        8: ["REPORT", "ASSESSMENT-REPORT", "FINAL-REPORT"],
    }

    # Directories to search in priority order
    search_dirs = []

    # 1. Session directory
    if session_id:
        session_dir = get_phase_working_dir(project_root) / session_id
        if session_dir.exists():
            search_dirs.append(session_dir)
    else:
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            search_dirs.append(current_session_dir)

    # 2. Report directory
    if report_dir.exists():
        search_dirs.append(report_dir)

    # 3. Phase working directory (legacy)
    phase_working = get_phase_working_dir(project_root)
    if phase_working.exists():
        search_dirs.append(phase_working)

    # Search for file
    for search_dir in search_dirs:
        # Try P{N}-*.md pattern first
        for pattern in phase_patterns:
            matches = list(search_dir.glob(pattern))
            if matches:
                # Return most recently modified
                return max(matches, key=lambda p: p.stat().st_mtime)

        # Try phase-specific name patterns
        name_patterns = phase_name_patterns.get(phase, [])
        for name_pattern in name_patterns:
            for f in search_dir.glob("*.md"):
                if name_pattern.upper() in f.name.upper():
                    return f

    return None


def _generate_phase_summary(phase: int, phase_data: Dict) -> Dict:
    """
    Generate a summary of phase data for handoff to next phase.

    Args:
        phase: Phase number
        phase_data: Extracted phase data

    Returns:
        Dict with summary information
    """
    if not phase_data:
        return {"error": "No phase data available"}

    blocks = phase_data.get("blocks", {})
    summary = {
        "phase": phase,
        "extracted_at": phase_data.get("extracted_at"),
        "block_count": len(blocks),
    }

    # Phase-specific summaries
    if phase == 1:
        # P1: Module and entry point counts
        modules = blocks.get("module_inventory", {})
        entry_points = blocks.get("entry_point_inventory", {})
        checklist = blocks.get("discovery_checklist", {})

        if isinstance(modules, dict):
            summary["modules"] = _count_items(modules.get("modules", modules))
        elif isinstance(modules, list):
            summary["modules"] = len(modules)

        ep_count = 0
        if isinstance(entry_points, dict):
            for key in ["api_entries", "ui_entries", "system_entries", "hidden_entries"]:
                items = entry_points.get(key, [])
                if isinstance(items, list):
                    ep_count += len(items)
        summary["entry_points"] = ep_count

        if isinstance(checklist, dict):
            checklist_summary = checklist.get("summary", {})
            summary["coverage"] = checklist_summary.get("coverage", "N/A")
            summary["discovery_complete"] = all(
                checklist.get("checklist", {}).get(ep_type, {}).get("scanned", False)
                for ep_type in ENTRY_POINT_TYPES
                if ep_type in checklist.get("checklist", {})
            )

    elif phase == 2:
        # P2: DFD elements and data flows
        dfd_elements = blocks.get("dfd_elements", {})
        data_flows = blocks.get("data_flows", {})

        if isinstance(dfd_elements, dict):
            elements = dfd_elements.get("elements", [])
            summary["dfd_elements"] = len(elements) if isinstance(elements, list) else _count_items(elements)

            # Count by type
            type_counts = {}
            if isinstance(elements, list):
                for elem in elements:
                    if isinstance(elem, dict):
                        elem_type = elem.get("type", "unknown")
                        type_counts[elem_type] = type_counts.get(elem_type, 0) + 1
            summary["elements_by_type"] = type_counts

        if isinstance(data_flows, dict):
            flows = data_flows.get("flows", [])
            summary["data_flows"] = len(flows) if isinstance(flows, list) else _count_items(flows)

            # L1 coverage
            l1_coverage = data_flows.get("l1_coverage", {})
            if l1_coverage:
                summary["l1_coverage"] = f"{l1_coverage.get('coverage_percentage', 0)}%"

    elif phase == 3:
        # P3: Trust boundaries
        # P3 typically outputs tables, not YAML blocks
        summary["note"] = "P3 outputs Markdown tables, not YAML blocks"
        for block_name, data in blocks.items():
            summary[block_name] = _count_items(data)

    elif phase == 4:
        # P4: Security design review
        # P4 typically outputs tables, not YAML blocks
        summary["note"] = "P4 outputs Markdown tables, not YAML blocks"
        for block_name, data in blocks.items():
            summary[block_name] = _count_items(data)

    elif phase == 5:
        # P5: Threat inventory
        threat_inventory = blocks.get("threat_inventory", {})

        if isinstance(threat_inventory, dict):
            threats = threat_inventory.get("threats", [])
            summary["threats"] = len(threats) if isinstance(threats, list) else _count_items(threats)

            # Count by STRIDE category
            stride_counts = {"S": 0, "T": 0, "R": 0, "I": 0, "D": 0, "E": 0}
            if isinstance(threats, list):
                for threat in threats:
                    if isinstance(threat, dict):
                        threat_id = threat.get("id", "") or threat.get("threat_id", "")
                        # Extract STRIDE letter from T-X-... format
                        if threat_id and len(threat_id) > 2 and threat_id.startswith("T-"):
                            stride_letter = threat_id[2]
                            if stride_letter in stride_counts:
                                stride_counts[stride_letter] += 1
            summary["threats_by_stride"] = stride_counts
        elif isinstance(threat_inventory, list):
            summary["threats"] = len(threat_inventory)

    elif phase == 6:
        # P6: Validated risks
        validated_risks = blocks.get("validated_risks", {})
        attack_paths = blocks.get("attack_paths", {})

        if isinstance(validated_risks, dict):
            risks = validated_risks.get("risks", [])
            summary["validated_risks"] = len(risks) if isinstance(risks, list) else _count_items(risks)

            # Excluded threats
            excluded = validated_risks.get("excluded_threats", [])
            if isinstance(excluded, list):
                summary["excluded_threats"] = len(excluded)
        elif isinstance(validated_risks, list):
            summary["validated_risks"] = len(validated_risks)

        if attack_paths:
            if isinstance(attack_paths, dict):
                paths = attack_paths.get("paths", [])
                summary["attack_paths"] = len(paths) if isinstance(paths, list) else _count_items(paths)
            elif isinstance(attack_paths, list):
                summary["attack_paths"] = len(attack_paths)

    elif phase == 7:
        # P7: Mitigation plan
        mitigation_plan = blocks.get("mitigation_plan", {})

        if isinstance(mitigation_plan, dict):
            mitigations = mitigation_plan.get("mitigations", [])
            summary["mitigations"] = len(mitigations) if isinstance(mitigations, list) else _count_items(mitigations)

            # Count by priority if available
            priority_counts = {}
            if isinstance(mitigations, list):
                for mit in mitigations:
                    if isinstance(mit, dict):
                        priority = mit.get("priority", "unspecified")
                        priority_counts[priority] = priority_counts.get(priority, 0) + 1
            if priority_counts:
                summary["mitigations_by_priority"] = priority_counts
        elif isinstance(mitigation_plan, list):
            summary["mitigations"] = len(mitigation_plan)

    # Add block names for all phases
    summary["blocks"] = list(blocks.keys())

    return summary


def phase_end_protocol(
    phase: int,
    project_root: str,
    markdown_file: Optional[str] = None,
    session_id: Optional[str] = None
) -> Dict:
    """
    Execute Phase End Protocol (extract + validate + summary).

    This is a complete phase completion workflow that:
    1. Extracts YAML blocks from the phase's Markdown report
    2. Validates phase completion against requirements
    3. Generates a summary for handoff to the next phase
    4. Updates session state to mark phase as completed

    Args:
        phase: Phase number (1-8)
        project_root: Project root directory
        markdown_file: Optional markdown file path (auto-detect if not provided)
        session_id: Optional session ID (uses current session if not specified)

    Returns:
        Dict with:
        - phase: Phase number
        - extraction: Extraction result
        - validation: Validation result
        - summary: Data summary for next phase
        - overall_status: "success" | "warning" | "blocking"
        - next_phase_query: Command to query this data for next phase
    """
    result = {
        "phase": phase,
        "action": "phase_end_protocol",
        "extraction": None,
        "validation": None,
        "summary": None,
        "overall_status": None,
        "next_phase": None,
        "executed_at": datetime.now().isoformat(),
    }

    # Validate phase number
    if phase < 1 or phase > 8:
        result["overall_status"] = "error"
        result["error"] = f"Invalid phase number: {phase}. Must be 1-8."
        return result

    # Determine session ID if not provided
    if not session_id:
        current_session_dir = get_current_session_dir(project_root)
        if current_session_dir:
            session_id = current_session_dir.name

    result["session_id"] = session_id

    # Step 1: Find markdown file
    md_path = None
    if markdown_file:
        md_path = Path(markdown_file)
        if not md_path.is_absolute():
            md_path = Path(project_root) / "Risk_Assessment_Report" / markdown_file
    else:
        md_path = _auto_detect_markdown_file(phase, project_root, session_id)

    if not md_path or not md_path.exists():
        result["overall_status"] = "error"
        result["error"] = f"Markdown file not found for phase {phase}"
        result["hint"] = f"Expected file pattern: P{phase}-*.md in Risk_Assessment_Report/"
        if markdown_file:
            result["searched_for"] = str(md_path)
        return result

    result["source_file"] = str(md_path)

    # Step 2: Extract YAML blocks
    extraction_result = extract_from_markdown(
        str(md_path),
        phase,
        project_root,
        session_id=session_id
    )

    result["extraction"] = extraction_result

    if extraction_result.get("error"):
        result["overall_status"] = "error"
        result["error"] = extraction_result["error"]
        return result

    if extraction_result.get("status") == "warning" and extraction_result.get("blocks_extracted", 0) == 0:
        # No YAML blocks found - check if this phase uses tables instead
        if phase in [3, 4]:
            # P3/P4 use Markdown tables, not YAML blocks
            result["extraction"]["note"] = f"Phase {phase} uses Markdown tables, not YAML blocks per WORKFLOW.md"
            result["extraction"]["status"] = "partial"
        else:
            result["overall_status"] = "warning"
            result["warning"] = "No YAML blocks extracted from markdown file"
            result["hint"] = "Ensure blocks use ```yaml:{block_name} format"

    # Step 3: Validate phase completion
    validation_result = validate_phase(phase, project_root)
    result["validation"] = validation_result

    # Determine validation status
    validation_status = validation_result.get("status", "unknown")

    # Step 4: Generate summary for next phase
    phase_data = load_phase_data(phase, project_root, session_id=session_id)
    summary = _generate_phase_summary(phase, phase_data)
    result["summary"] = summary

    # Step 5: Update session state
    session = load_session(project_root, session_id)
    if session:
        # Update phases_completed
        phases_completed = session.get("phases_completed", [])
        if phase not in phases_completed:
            phases_completed.append(phase)
            phases_completed.sort()

        # Update current_phase to next phase
        next_phase_num = phase + 1 if phase < 8 else 8

        updates = {
            "phases_completed": phases_completed,
            "current_phase": next_phase_num,
            "last_phase_end_protocol": {
                "phase": phase,
                "executed_at": result["executed_at"],
                "status": validation_status,
            },
        }

        # Also update extraction_status
        if "extraction_status" not in session:
            session["extraction_status"] = {}

        session["extraction_status"][f"phase{phase}"] = {
            "extracted": True,
            "entities": extraction_result.get("blocks_extracted", 0),
            "blocks": list(extraction_result.get("blocks", {}).keys()),
            "phase_end_completed": True,
        }
        updates["extraction_status"] = session["extraction_status"]

        update_result = update_session(project_root, updates, session_id)
        result["session_updated"] = update_result.get("status") == "success"

        # Also update session meta for multi-version sessions
        if session_id:
            _update_session_meta(
                project_root,
                session_id,
                session.get("project_name", ""),
                "update",
                current_phase=next_phase_num,
                phases_completed=phases_completed
            )

    # Step 6: Prepare next phase info
    next_phase_num = phase + 1 if phase < 8 else None

    if next_phase_num:
        next_phase_deps = PHASE_DEPENDENCIES.get(next_phase_num, {})
        result["next_phase"] = {
            "phase": next_phase_num,
            "depends_on": next_phase_deps.get("requires", []),
            "description": next_phase_deps.get("description", ""),
            "query_command": f"python scripts/phase_data.py {next_phase_deps.get('query', '--query --phase ' + str(phase) + ' --summary')} --root {project_root}",
        }
    else:
        result["next_phase"] = {
            "phase": None,
            "message": "Phase 8 is the final phase. Workflow complete!",
        }

    # Step 7: Determine overall status
    if validation_status == "blocking":
        result["overall_status"] = "blocking"
        result["message"] = f"Phase {phase} has blocking issues that must be resolved before proceeding."
        result["action_required"] = "Fix blocking issues listed in validation result."
    elif validation_status == "warning" or extraction_result.get("status") == "warning":
        result["overall_status"] = "warning"
        result["message"] = f"Phase {phase} completed with warnings. Review before proceeding to Phase {next_phase_num}."
    elif validation_status == "passed" or validation_status == "success":
        result["overall_status"] = "success"
        result["message"] = f"Phase {phase} completed successfully. Ready for Phase {next_phase_num}." if next_phase_num else f"Phase {phase} completed. Workflow complete!"
    elif validation_status == "error":
        result["overall_status"] = "error"
        result["message"] = f"Phase {phase} validation encountered an error."
    else:
        # For phases without specific validation (P3, P4)
        if extraction_result.get("status") == "success" or extraction_result.get("blocks_extracted", 0) > 0:
            result["overall_status"] = "success"
            result["message"] = f"Phase {phase} data extracted. Ready for Phase {next_phase_num}." if next_phase_num else "Workflow complete!"
        else:
            result["overall_status"] = "warning"
            result["message"] = f"Phase {phase} completed but no structured data extracted."

    return result


# ============================================================================
# Main CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase data manager for STRIDE threat modeling workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Session Management (Multi-Version)
    python phase_data.py --init --project "OPEN-WEBUI" --path /path/to/project
    python phase_data.py --init --project "OPEN-WEBUI" --force   # Force new session
    python phase_data.py --check-session --root /path/to/project
    python phase_data.py --resume --root /path/to/project
    python phase_data.py --resume --session-id OPEN-WEBUI-20260129_150000
    python phase_data.py --list-sessions --root /path/to/project
    python phase_data.py --migrate-session --root /path/to/project

    # Extract YAML blocks from Markdown (Option C - Primary)
    python phase_data.py --extract P1-PROJECT-UNDERSTANDING.md --phase 1 --root /path/to/project

    # Query phase data
    python phase_data.py --query --phase 1 --summary --root /path/to/project
    python phase_data.py --query --phase 1 --type entry_points --root /path/to/project
    python phase_data.py --query --phase 2 --element P-001 --root /path/to/project
    python phase_data.py --query --threats-for-element P-013 --root /path/to/project
    python phase_data.py --query --phase 1 --session-id OPEN-WEBUI-20260129_150000

    # Validate phase completion
    python phase_data.py --validate --phase 1 --root /path/to/project
    python phase_data.py --validate --phase 2 --root /path/to/project

    # Checkpoint validations (CP1/CP2/CP3)
    python phase_data.py --validate-cp1 --root /path/to/project
    python phase_data.py --validate-cp2 --root /path/to/project
    python phase_data.py --validate-cp3 --root /path/to/project
    python phase_data.py --validate-all-cp --root /path/to/project

    # ID format validation
    python phase_data.py --validate-ids --phase 5 --root /path/to/project

    # Workflow validation
    python phase_data.py --validate-workflow --root /path/to/project

    # Phase End Protocol (extract + validate + summary in one step)
    python phase_data.py --phase-end --phase 1 --root /path/to/project
    python phase_data.py --phase-end --phase 2 --file P2-DFD-ANALYSIS.md --root /path/to/project
    python phase_data.py --phase-end --phase 5 --session-id OPEN-WEBUI-20260129_150000 --root .

    # Backward compatibility (direct markdown parsing)
    python phase_data.py --validate-cp1 --markdown-mode --root /path/to/project

    # Store JSON directly (Option B - Backup)
    python phase_data.py --store --phase 5 --input-json threats.json --root /path/to/project

    # Cross-phase aggregation
    python phase_data.py --aggregate --phases 1,2,5 --format summary --root /path/to/project
        """
    )

    # Command modes
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--init",
        action="store_true",
        help="Initialize session (creates new multi-version session)"
    )
    mode_group.add_argument(
        "--check-session",
        action="store_true",
        help="Check for incomplete sessions"
    )
    mode_group.add_argument(
        "--resume",
        action="store_true",
        help="Resume most recent incomplete session"
    )
    mode_group.add_argument(
        "--list-sessions",
        action="store_true",
        help="List all sessions for the project"
    )
    mode_group.add_argument(
        "--migrate-session",
        action="store_true",
        help="Migrate legacy single-file session to new multi-version structure"
    )
    mode_group.add_argument(
        "--extract",
        metavar="FILE",
        help="Extract YAML blocks from Markdown file (Option C)"
    )
    mode_group.add_argument(
        "--store",
        action="store_true",
        help="Store JSON input directly (Option B)"
    )
    mode_group.add_argument(
        "--query",
        action="store_true",
        help="Query phase data"
    )
    mode_group.add_argument(
        "--validate",
        action="store_true",
        help="Validate phase completion"
    )
    mode_group.add_argument(
        "--aggregate",
        action="store_true",
        help="Aggregate multiple phases"
    )
    mode_group.add_argument(
        "--status",
        action="store_true",
        help="Show session status"
    )
    mode_group.add_argument(
        "--validate-cp1",
        action="store_true",
        help="CP1: Validate P5→P6 threat count conservation"
    )
    mode_group.add_argument(
        "--validate-cp2",
        action="store_true",
        help="CP2: Validate VR threat_refs completeness"
    )
    mode_group.add_argument(
        "--validate-cp3",
        action="store_true",
        help="CP3: Validate P6→Reports VR count conservation"
    )
    mode_group.add_argument(
        "--validate-all-cp",
        action="store_true",
        help="Execute all checkpoint validations (CP1+CP2+CP3)"
    )
    mode_group.add_argument(
        "--validate-ids",
        action="store_true",
        help="Validate ID formats in a phase"
    )
    mode_group.add_argument(
        "--validate-workflow",
        action="store_true",
        help="Validate complete workflow integrity"
    )
    mode_group.add_argument(
        "--phase-end",
        action="store_true",
        help="Execute Phase End Protocol: extract + validate + summary for phase handoff"
    )

    # Common arguments
    parser.add_argument(
        "--root", "-r",
        metavar="PATH",
        default=".",
        help="Project root directory (default: current directory)"
    )
    parser.add_argument(
        "--phase", "-p",
        type=int,
        choices=range(1, 9),
        help="Phase number (1-8)"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output"
    )

    # Init arguments
    parser.add_argument(
        "--project",
        metavar="NAME",
        help="Project name (for --init)"
    )
    parser.add_argument(
        "--path",
        metavar="PATH",
        help="Project path (for --init)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force action (e.g., create new session even with incomplete sessions)"
    )

    # Session management arguments
    parser.add_argument(
        "--session-id",
        metavar="ID",
        help="Specific session ID (for --resume, --query, --extract, --phase-end)"
    )

    # Phase End Protocol arguments
    parser.add_argument(
        "--file", "-f",
        metavar="FILE",
        help="Markdown file for --phase-end (auto-detected if not provided)"
    )

    # Store arguments (Option B)
    parser.add_argument(
        "--input-json",
        metavar="FILE",
        help="JSON file to store (for --store)"
    )
    parser.add_argument(
        "--block",
        metavar="NAME",
        help="Block name for JSON storage"
    )

    # Query arguments
    parser.add_argument(
        "--type", "-t",
        metavar="TYPE",
        help="Query type (entry_points, modules, threats, etc.)"
    )
    parser.add_argument(
        "--element", "-e",
        metavar="ID",
        help="Element ID to query"
    )
    parser.add_argument(
        "--threats-for-element",
        metavar="ID",
        help="Query threats for specific element"
    )
    parser.add_argument(
        "--summary", "-s",
        action="store_true",
        help="Return summary instead of full data"
    )

    # Aggregate arguments
    parser.add_argument(
        "--phases",
        metavar="LIST",
        help="Comma-separated phase numbers (e.g., 1,2,5)"
    )
    parser.add_argument(
        "--format",
        choices=["summary", "full"],
        default="summary",
        help="Aggregation format"
    )

    # Validation mode argument
    parser.add_argument(
        "--markdown-mode",
        action="store_true",
        help="Use direct markdown parsing (backward compatible with validate_count_conservation.py)"
    )

    args = parser.parse_args()

    # Execute command
    result = None

    if args.init:
        if not args.project:
            parser.error("--init requires --project")
        project_path = args.path or args.root
        result = init_session(args.project, project_path, force=args.force)

    elif args.check_session:
        result = check_session(args.root)

    elif args.resume:
        result = resume_session(args.root, session_id=args.session_id)

    elif args.list_sessions:
        result = list_sessions(args.root)

    elif args.migrate_session:
        result = migrate_legacy_session(args.root)

    elif args.extract:
        if not args.phase:
            parser.error("--extract requires --phase")
        result = extract_from_markdown(
            args.extract,
            args.phase,
            args.root,
            session_id=args.session_id
        )

    elif args.store:
        if not args.phase or not args.input_json:
            parser.error("--store requires --phase and --input-json")
        result = store_json(args.input_json, args.phase, args.root, args.block)

    elif args.query:
        if args.threats_for_element:
            result = query_threats_for_element(args.threats_for_element, args.root)
        elif args.phase:
            result = query_phase(
                args.phase,
                args.root,
                query_type=args.type,
                element_id=args.element,
                summary=args.summary
            )
        else:
            parser.error("--query requires --phase or --threats-for-element")

    elif args.validate:
        if not args.phase:
            parser.error("--validate requires --phase")
        result = validate_phase(args.phase, args.root)

    elif args.aggregate:
        if not args.phases:
            parser.error("--aggregate requires --phases")
        phase_list = [int(p.strip()) for p in args.phases.split(",")]
        result = aggregate_phases(phase_list, args.root, args.format)

    elif args.status:
        session = load_session(args.root, session_id=args.session_id)
        if session:
            result = {
                "status": "active",
                "session": session,
            }
        else:
            result = {
                "status": "no_session",
                "message": "No active session. Run --init to start.",
            }

    # Checkpoint validations
    elif args.validate_cp1:
        result = validate_cp1_threat_conservation(args.root, args.markdown_mode)

    elif args.validate_cp2:
        result = validate_cp2_vr_threat_refs(args.root, args.markdown_mode)

    elif args.validate_cp3:
        result = validate_cp3_report_conservation(args.root)

    elif args.validate_all_cp:
        result = validate_all_checkpoints(args.root, args.markdown_mode)

    elif args.validate_ids:
        if not args.phase:
            parser.error("--validate-ids requires --phase")
        result = validate_id_formats_in_phase(args.phase, args.root)

    elif args.validate_workflow:
        result = validate_workflow_complete(args.root)

    elif args.phase_end:
        if not args.phase:
            parser.error("--phase-end requires --phase")
        result = phase_end_protocol(
            args.phase,
            args.root,
            markdown_file=args.file,
            session_id=args.session_id
        )

    # Output JSON
    if result:
        if args.pretty:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
