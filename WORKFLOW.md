<!-- Threat Modeling Skill | Version 3.0.2 (20260204a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# WORKFLOW.md - Orchestration Contracts

**Version**: 3.0.1 (20260203a)
**Purpose**: Phase orchestration, **structured data contracts**, validation gates, **FSM-enforced execution**

> **Cross-References**:
> - Global constraints and data model: See SKILL.md
> - FSM formal specification: See docs/SKILL-ARCHITECTURE-DESIGN.md §0.1-0.2

---

## §1 Workflow State Machine (FSM)

### 8-Phase FSM Definition

```
┌─────────────────────────────────────────────────────────────────┐
│                    STRIDE Threat Modeling FSM                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  States: {INIT, P1, P2, P3, P4, P5, P6, P7, P8, DONE, ERROR}    │
│                                                                  │
│  Transitions:                                                    │
│    δ(INIT, start) → P1                                          │
│    δ(Pn, pn_complete) → P(n+1)  where n ∈ {1..7}                │
│    δ(P8, p8_complete) → DONE                                    │
│    δ(Pn, validation_fail) → ERROR                               │
│    δ(ERROR, recovery_success) → Pn  (rollback)                  │
│                                                                  │
│  Accepting States: {DONE}                                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### State Transition Diagram

```
    INIT ──start──► P1 ──p1_complete──► P2 ──► P3 ──► P4 ──► P5 ──► P6 ──► P7 ──► P8 ──► DONE
                     │                   │      │      │      │      │      │      │
                     └─validation_fail──►├──────┴──────┴──────┴──────┴──────┴──────┘
                                         ▼
                                       ERROR ──recovery_success──► (rollback to last valid Pn)
```

### Phase Internal 4-Gate Sub-FSM

Each Phase Pn internally follows:

```
ENTRY ──[check_pass]──► THINKING ──► PLANNING ──► EXECUTING ◄──loop──► REFLECTING ──► EXIT
  │                                                                                      │
  └──[check_fail]────────────────────────────────────────────────────────────────────────┘
                                                                            (emit pn_complete)
```

> **Entry Gate Details**: See each `@phases/P{N}-*.md` file

---

## §1.1 Data Flow Architecture

> **Principle**: YAML is data (machine-readable), Markdown is report (human-readable). Separate concerns!
> **Directory structure definition**: See SKILL.md §2.2

```
DATA FLOW CHAIN (strict, no gaps):
  P1 → writes P1_project_context.yaml → P2 reads it
  P2 → writes P2_dfd_elements.yaml → P3 reads it
  ...
  P7 → writes P7_mitigation_plan.yaml → P8 reads it

❌ FORBIDDEN: P{N+1} reading P{N}'s .md report for data extraction
✅ REQUIRED: P{N+1} reading P{N}'s .yaml data file directly
```

---

## §1.2 Session Initialization

### Session ID Generation

> **Format Definition**: See SKILL.md §2.4

```
SESSION_ID = {PROJECT_NAME}_{YYYYMMDD_HHMMSS}
Example: OPEN-WEBUI_20260130_143022
```

### Directory Creation

```bash
SESSION_ID="${PROJECT_NAME}_$(date +%Y%m%d_%H%M%S)"
mkdir -p ".phase_working/${SESSION_ID}/data"
mkdir -p ".phase_working/${SESSION_ID}/reports"
```

### Session Metadata Schema

```yaml
# .phase_working/{SESSION_ID}/_session_meta.yaml
schema_version: "3.0.1 (20260203a)"
session_id: "{PROJECT}_{YYYYMMDD_HHMMSS}"
project_name: "PROJECT-NAME"
project_path: "/absolute/path"
started_at: "ISO8601"
language: "en"                    # en|zh|ja|ko
skill_version: "3.0.1 (20260203a)"
current_state: "P1"               # FSM current state

phases:
  P{N}:
    status: "pending|in_progress|completed|failed"
    started_at: null
    completed_at: null
    data_file: "data/P{N}_*.yaml"
    report_file: "reports/P{N}-*.md"
    validation:
      exit_code: null
      errors: []
```

### Sessions Index (Optional)

```yaml
# .phase_working/_sessions_index.yaml
sessions:
  - session_id: "OPEN-WEBUI_20260130_143022"
    project_name: "OPEN-WEBUI"
    started_at: "2026-01-30T14:30:22Z"
    status: "completed"
    current_phase: 8
  - session_id: "OPEN-WEBUI_20260129_100000"
    project_name: "OPEN-WEBUI"
    started_at: "2026-01-29T10:00:00Z"
    status: "completed"
    current_phase: 8
```

### Todo Creation

Create 8 items at session start:

```json
[
  {"content": "Phase 1: Project Understanding", "status": "pending"},
  {"content": "Phase 2: Call Flow & DFD Analysis", "status": "pending"},
  {"content": "Phase 3: Trust Boundary Evaluation", "status": "pending"},
  {"content": "Phase 4: Security Design Review", "status": "pending"},
  {"content": "Phase 5: STRIDE Threat Analysis", "status": "pending"},
  {"content": "Phase 6: Risk Validation", "status": "pending"},
  {"content": "Phase 7: Mitigation Planning", "status": "pending"},
  {"content": "Phase 8: Report Generation", "status": "pending"}
]
```

---

## §2 Phase Execution Protocol

> **FSM Enforcement**: Phase transitions are governed by the FSM defined in §1.
> **Entry Gate Details**: See `@phases/P{N}-*.md` for per-phase 4-Gate protocol.
> **Global Constraints**: See SKILL.md §10-11 for execution invariants.

### Phase Execution Algorithm

```
FOR each phase N in [1..8]:
  1. PRECONDITION: current_state == P{N-1}.completed (except P1)
  2. Read @phases/P{N}-*.md (instructions)
  3. Execute 4-Gate: ENTRY → THINKING → PLANNING → EXECUTING → REFLECTING → EXIT
  4. Write: data/P{N}_*.yaml (PRIMARY)
  5. Write: reports/P{N}-*.md (SECONDARY)
  6. PostToolUse hook validates YAML
  7. IF exit_code == 0: δ(P{N}, p{n}_complete) → P{N+1}
  8. IF exit_code != 0: δ(P{N}, validation_fail) → ERROR, then fix and retry
```

### Checkpoint Phases (User Confirmation Required)

| Phase | Checkpoint | Purpose |
|-------|------------|---------|
| P5 | After threat enumeration | User confirms threat list completeness |
| P6 | After risk validation | User confirms attack paths before mitigation |
| P7 | After mitigation planning | User confirms remediation plan before report |

---

## §3 Phase Data Contracts (YAML Files)

> **Complete Schema Definitions**: See `@assets/contracts/data-model.yaml`

### Contract Summary Table

| Phase | File | Key Fields | Validation |
|-------|------|------------|------------|
| P1 | `P1_project_context.yaml` | module_inventory, entry_point_inventory, discovery_checklist | checklist.coverage == 100% |
| P2 | `P2_dfd_elements.yaml` | interface_inventory, data_flow_traces, dfd_elements | l1_coverage == 100% |
| P3 | `P3_boundary_context.yaml` | boundaries[], interfaces[], cross_boundary_flows[] | boundaries non-empty |
| P4 | `P4_security_gaps.yaml` | gaps[], design_matrix (16 domains), findings[] | 16 domains assessed |
| P5 | `P5_threat_inventory.yaml` | threats[], summary (by_stride, by_element, by_risk) | total > 0 |
| P6 | `P6_validated_risks.yaml` | risk_details[], poc_details[], attack_paths[] | count conservation |
| P7 | `P7_mitigation_plan.yaml` | mitigations[], roadmap (P0-P3) | every VR has MIT |
| P8 | `P8_report_manifest.yaml` | generated_reports[], statistics | all reports generated |

### Common Header (All Phases)

```yaml
schema_version: "3.0.1 (20260203a)"
phase: {N}
generated_at: "ISO8601"
input_ref: "P{N-1}_*.yaml"  # Traceability (except P1)
```

### P5 Threat ID Format

```yaml
# Threat ID: T-{STRIDE}-{ElementID}-{Seq}
# Example: T-S-P001-001 (Spoofing threat for Process P-001)
threats:
  - id: T-S-P001-001
    stride_category: "S"
    element_id: "P-001"
    cwe_refs: ["CWE-287"]
    capec_refs: ["CAPEC-151"]
```

### P6 Count Conservation (CRITICAL)

```yaml
risk_summary:
  total_identified: 45      # From P5
  total_verified: 15        # Exploitable
  total_theoretical: 20     # Possible
  total_pending: 5          # Under investigation
  total_excluded: 5         # False positives
  # INVARIANT: 15 + 20 + 5 + 5 = 45

risk_details:
  - id: VR-001
    threat_refs: ["T-S-P001-001"]  # Links back to P5
    validation_status: "verified|theoretical|pending|excluded"
```

### P7 Mitigation Priority

```yaml
mitigation_plan:
  mitigations:
    - id: MIT-001
      risk_refs: ["VR-001"]  # Links back to P6
      priority: "P0|P1|P2|P3"
  roadmap:
    immediate: ["MIT-001"]   # P0: Fix now
    short_term: ["MIT-003"]  # P1: 7 days
    medium_term: ["MIT-004"] # P2: 30 days
    long_term: ["MIT-006"]   # P3: Backlog
```

---

## §4 Validation Gates

### Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Pass | Proceed to next phase |
| 1 | Missing data | Fix YAML and revalidate |
| 2 | Schema validation failed | Fix structure and revalidate |

### Phase-Specific Validation

| Phase | Data File Required | Validation Criteria |
|-------|-------------------|---------------------|
| 1 | P1_project_context.yaml | module_inventory + entry_point_inventory + discovery_checklist |
| 2 | P2_dfd_elements.yaml | l1_coverage.coverage_percentage == 100 |
| 3 | P3_boundary_context.yaml | boundaries[] non-empty |
| 4 | P4_security_gaps.yaml | design_matrix with 16 domains |
| 5 | P5_threat_inventory.yaml | threat_inventory.summary.total > 0 |
| 6 | P6_validated_risks.yaml | Count conservation balanced |
| 7 | P7_mitigation_plan.yaml | Every VR-xxx has MIT-xxx |
| 8 | P8_report_manifest.yaml | All 8 reports generated |

### Count Conservation

```
P5.threat_inventory.summary.total ==
  P6.risk_summary.total_verified +
  P6.risk_summary.total_theoretical +
  P6.risk_summary.total_pending +
  P6.risk_summary.total_excluded
```

---

## §5 STRIDE per Element Matrix

| Element Type | S | T | R | I | D | E |
|--------------|---|---|---|---|---|---|
| Process      | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data Store   |   | ✓ | ✓ | ✓ | ✓ |   |
| Data Flow    |   | ✓ |   | ✓ | ✓ |   |
| External (source) | ✓ |   | ✓ |   |   |   |

---

## §6 Error Recovery

### Validation Failure

1. Read error message from validation output
2. Identify missing/invalid fields in YAML
3. Fix YAML data file
4. Re-run validation
5. Only then update report

### Session Interruption

1. Check `.phase_working/{SESSION_ID}/_session_meta.yaml`
2. Find last phase with `status: "completed"`
3. Load that phase's YAML data file from `data/` subdirectory
4. Resume from next phase

> **SESSION_ID Format**: `{PROJECT_NAME}_{YYYYMMDD_HHMMSS}`
> Example: `OPEN-WEBUI_20260130_143022`

---

## §7 Final Report Output

> **Directory Structure**: See SKILL.md §2.2 for complete structure
> **Naming Convention**: See SKILL.md §2.3

### Report Summary

| Category | Files | Source |
|----------|-------|--------|
| Required (4) | RISK-ASSESSMENT-REPORT, RISK-INVENTORY, MITIGATION-MEASURES, PENETRATION-TEST-PLAN | P6-P8 YAML |
| Extended (4) | ARCHITECTURE-ANALYSIS, DFD-DIAGRAM, COMPLIANCE-REPORT, ATTACK-PATH-VALIDATION | P1-P7 YAML |
| Phase (7) | P1-P7-*.md | Phase execution |

### Multi-Session Support

```
.phase_working/
├── _sessions_index.yaml                   ← Optional session index
├── {PROJECT}_{YYYYMMDD_HHMMSS}/          ← Historical sessions
└── {PROJECT}_{YYYYMMDD_HHMMSS}/          ← Current session (active)
```

> **Session isolation enables**: Incremental analysis, historical comparison, rollback capability

---

**End of WORKFLOW.md** (~380 lines, ~4.5K tokens)
