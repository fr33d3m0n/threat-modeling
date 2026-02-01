<!-- Threat Modeling Skill | Version 3.0.0 (20260201a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# WORKFLOW.md - Orchestration Contracts

**Version**: 3.0.0 (20260201a)
**Purpose**: Phase orchestration, **structured data contracts**, validation gates, **gating protocol**

---

## ⚠️ CRITICAL: Data Flow Architecture

> **PRINCIPLE**: Markdown 是报告，YAML/JSON 是数据。两者必须分离！

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    STRICT DATA FLOW ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  .phase_working/                                                         │
│  ├── {SESSION_ID}/              ← Session isolation directory            │
│  │   ├── _session_meta.yaml     ← Session state (machine-readable)      │
│  │   ├── data/                  ← STRUCTURED DATA (for inter-phase)     │
│  │   │   ├── P1_project_context.yaml                                    │
│  │   │   ├── P2_dfd_elements.yaml                                       │
│  │   │   ├── P3_boundary_context.yaml                                   │
│  │   │   ├── P4_security_gaps.yaml                                      │
│  │   │   ├── P5_threat_inventory.yaml                                   │
│  │   │   ├── P6_validated_risks.yaml                                    │
│  │   │   ├── P7_mitigation_plan.yaml                                    │
│  │   │   └── P8_report_manifest.yaml                                    │
│  │   └── reports/               ← HUMAN-READABLE REPORTS                │
│  │       ├── P1-PROJECT-UNDERSTANDING.md                                │
│  │       ├── P2-DFD-ANALYSIS.md                                         │
│  │       ├── P3-TRUST-BOUNDARY.md                                       │
│  │       ├── P4-SECURITY-DESIGN-REVIEW.md                               │
│  │       ├── P5-STRIDE-THREATS.md                                       │
│  │       ├── P6-RISK-VALIDATION.md                                      │
│  │       └── P7-MITIGATION-PLAN.md                                      │
│  └── _sessions_index.yaml       ← All sessions index (optional)         │
│                                                                          │
│  SESSION_ID FORMAT: {PROJECT_NAME}_{YYYYMMDD_HHMMSS}                    │
│  EXAMPLE: OPEN-WEBUI_20260130_143022                                     │
│                                                                          │
│  DATA FLOW:                                                              │
│  P1 → writes P1_project_context.yaml → P2 reads it                      │
│  P2 → writes P2_dfd_elements.yaml → P3 reads it                         │
│  ... (strict chain, no gaps)                                             │
│                                                                          │
│  ❌ FORBIDDEN: P2 reading P1's .md report for data extraction           │
│  ✅ REQUIRED: P2 reading P1's .yaml data file directly                  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## §1 Session Initialization

### Session ID Generation

```
SESSION_ID = {PROJECT_NAME}_{YYYYMMDD_HHMMSS}

Examples:
  OPEN-WEBUI_20260130_143022
  N8N_20260130_150000
  DIFY_20260131_091530
```

### Directory Creation

At session start, create:

```bash
SESSION_ID="${PROJECT_NAME}_$(date +%Y%m%d_%H%M%S)"
mkdir -p ".phase_working/${SESSION_ID}/data"
mkdir -p ".phase_working/${SESSION_ID}/reports"
```

### Session Metadata

```yaml
# .phase_working/{SESSION_ID}/_session_meta.yaml
schema_version: "3.0.0 (20260201a)"
session_id: "OPEN-WEBUI_20260130_143022"
project_name: "OPEN-WEBUI"
project_path: "/absolute/path/to/project"
started_at: "2026-01-30T14:30:22Z"
language: "en"                    # en|zh|ja|ko - Controls report output language
skill_version: "3.0.0 (20260201a)"

# Language Field Behavior:
# - "en": English reports, terminology, and recommendations
# - "zh": Chinese (Simplified) reports
# - "ja": Japanese reports
# - "ko": Korean reports
# Note: YAML data files always use English keys; language only affects
# human-readable reports (.md files) and recommendation text.

phases:
  P1:
    status: "pending"             # pending|in_progress|completed|failed
    started_at: null
    completed_at: null
    data_file: null               # Path to P1_project_context.yaml when done
    report_file: null             # Path to P1-*.md when done
    validation:
      exit_code: null
      errors: []
  P2:
    status: "pending"
    # ... same structure
  # P3-P8: same structure
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

## §2 Phase Execution Protocol (with Gating)

> **REFERENCE**: 核心执行规则见 SKILL.md §10 Core Execution Rules

### Per-Phase Workflow (Enhanced with Gating Protocol)

```
FOR each phase N in [1..8]:

  ┌─ ① PLANNING ───────────────────────────────────────────────────────────┐
  │                                                                         │
  │  1. STATE PHASE OBJECTIVE                                               │
  │     - Explicitly declare: "Phase {N} objective is..."                   │
  │     - Verify alignment with project goal                                │
  │                                                                         │
  │  2. LOAD & VERIFY INPUT DATA (except P1)                                │
  │     - Read .phase_working/data/P{N-1}_*.yaml                           │
  │     - Parse as structured data                                          │
  │     - ❌ DO NOT read previous .md reports for data                      │
  │     - ⚠️ STOP if input incomplete or malformed                         │
  │                                                                         │
  │  3. DECOMPOSE INTO SUB-TASKS                                            │
  │     - Break phase work into 3-7 sub-tasks                               │
  │     - Define input/output for each sub-task                             │
  │     - Create todos for tracking                                         │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
                                    ↓
  ┌─ ② EXECUTION LOOP ─────────────────────────────────────────────────────┐
  │                                                                         │
  │  4. UPDATE SESSION META                                                 │
  │     - Set phases.P{N}.status = "in_progress"                            │
  │     - Set phases.P{N}.started_at = now()                                │
  │                                                                         │
  │  5. EXECUTE ANALYSIS (per sub-task)                                     │
  │     - Follow @phases/P{N}-*.md instructions                             │
  │     - Query knowledge base as needed (log queries!)                     │
  │     - After each sub-task: verify alignment                             │
  │     - ⚠️ If issue found: STOP → fix → verify → continue                │
  │                                                                         │
  │  6. WRITE OUTPUT DATA (YAML first!)                                     │
  │     - Write .phase_working/data/P{N}_*.yaml                            │
  │     - Validate schema compliance                                        │
  │     - ✅ This is the PRIMARY output                                     │
  │                                                                         │
  │  7. WRITE REPORT (MD second)                                            │
  │     - Write .phase_working/reports/P{N}-*.md                           │
  │     - Reference data from YAML, format for humans                       │
  │     - ❌ This is SECONDARY, for human reading only                      │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
                                    ↓
  ┌─ ③ REFLECTION ─────────────────────────────────────────────────────────┐
  │                                                                         │
  │  8. VALIDATE & UPDATE META                                              │
  │     - Run phase_data.py --phase-end --phase {N}                        │
  │     - ⚠️ If validation fails: fix YAML, re-validate, iterate           │
  │                                                                         │
  │  9. VERIFY COMPLETENESS                                                 │
  │     - All sub-tasks completed?                                          │
  │     - All issues resolved?                                              │
  │     - Output aligns with phase objective?                               │
  │                                                                         │
  │  10. UPDATE SESSION & PROCEED                                           │
  │      - Update phases.P{N}.status = "completed"                          │
  │      - Set phases.P{N}.completed_at = now()                             │
  │      - Set phases.P{N}.data_file = path to YAML                        │
  │      - Set phases.P{N}.report_file = path to MD                        │
  │      - ✅ Only then proceed to Phase {N+1}                              │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## §3 Phase Data Contracts (YAML Files)

### P1 Output: `P1_project_context.yaml`

```yaml
# .phase_working/data/P1_project_context.yaml
schema_version: "3.0.0 (20260201a)"
phase: 1
generated_at: "ISO8601"

project_context:
  project_type: "web|api|microservices|ai|llm"
  project_name: "PROJECT-NAME"
  tech_stack:
    languages: ["Python", "TypeScript"]
    frameworks: ["FastAPI", "React"]
    databases: ["PostgreSQL", "Redis"]

module_inventory:
  modules:
    - id: M-001
      name: "Authentication Module"
      path: "src/auth"
      type: "Authentication"
      security_level: "HIGH"
      files: 12
      loc: 1500
      entry_types: ["API", "UI"]
  summary:
    total_modules: 15
    by_security_level: {HIGH: 5, MEDIUM: 7, LOW: 3}

entry_point_inventory:
  api_entries:
    - id: EP-API-001
      path: "/api/v1/auth/login"
      methods: ["POST"]
      module: "M-001"
      handler: "src/auth/handlers/login.py:45"
      auth_required: false
      exposure: "EXTERNAL"
  ui_entries: []
  system_entries: []
  hidden_entries: []
  summary:
    total_entry_points: 72
    by_type: {api: 45, ui: 12, system: 10, hidden: 5}

discovery_checklist:
  rest_api: {scanned: true, count: 45, status: "COMPLETED"}
  internal_api: {scanned: true, count: 8, status: "COMPLETED"}
  graphql: {scanned: true, count: 0, status: "NOT_APPLICABLE"}
  websocket: {scanned: true, count: 2, status: "COMPLETED"}
  cron_jobs: {scanned: true, count: 3, status: "COMPLETED"}
  message_queue: {scanned: true, count: 0, status: "NOT_APPLICABLE"}
  webhooks: {scanned: true, count: 2, status: "COMPLETED"}
  file_upload: {scanned: true, count: 3, status: "COMPLETED"}
  health_endpoints: {scanned: true, count: 3, status: "COMPLETED"}
  debug_endpoints: {scanned: true, count: 1, status: "COMPLETED"}
  coverage: "100%"

doc_analysis:  # Optional, only if docs exist
  analyzed_documents: []
  project_intent: {}
  architecture_overview: {}
```

### P2 Output: `P2_dfd_elements.yaml`

```yaml
# .phase_working/data/P2_dfd_elements.yaml
schema_version: "3.0.0 (20260201a)"
phase: 2
generated_at: "ISO8601"
input_ref: "P1_project_context.yaml"  # Traceability

interface_inventory:
  discovery_sources:
    openapi_spec: "api/openapi.yaml"
    static_analysis: true
    config_files: ["nginx.conf"]
  interfaces:
    - id: IF-001
      layer: "L1"
      type: "REST"
      path: "/api/v1/users"
      methods: ["GET", "POST", "PUT", "DELETE"]
      auth_required: true
      code_location: {file: "src/routes/users.py", line: 45}
      input_modalities:
        - type: "path_params"
          params: [{name: "user_id", type: "uuid"}]
        - type: "json_body"
          schema_ref: "UserCreateRequest"
  summary:
    total_interfaces: 45
    by_layer: {L1: 12, L2: 23, L3: 10}

data_flow_traces:
  flows:
    - id: DF-001
      name: "User Creation Data Flow"
      entry_interface: "IF-001"
      trace:
        - step: 1
          component: "UserRouter.create"
          action: "receive_request"
          data_in: "raw_json"
          data_out: "parsed_request"
        - step: 2
          component: "InputValidator.validate"
          action: "validate_input"
          security_relevant: true
      sensitive_data_points:
        - {step: 3, field: "password", classification: "credential"}
  summary:
    total_flows: 89
    sensitive_flows: 23

call_flow_graph:
  call_flows:
    - id: CF-001
      entry_interface: "IF-001"
      call_chain:
        - step: 1
          caller: "UserRouter.create"
          callee: "AuthMiddleware.verify"
          security_check: true
          check_type: "authentication"
      security_checkpoints:
        - {step: 1, type: "authentication", bypass_risk: "low"}
  summary:
    total_call_flows: 67
    security_checkpoint_coverage: 0.72

data_store_inventory:
  data_stores:
    - id: DS-001
      name: "Primary PostgreSQL"
      type: "relational_database"
      technology: "PostgreSQL"
      sensitive_data:
        - table: "users"
          fields:
            - {name: "password_hash", classification: "credential"}
            - {name: "email", classification: "PII"}
      security_config:
        encryption_at_rest: true
        encryption_in_transit: true
  summary:
    total_data_stores: 5
    encryption_coverage: 0.83

dfd_elements:
  external_interactors:
    - id: EI-001
      name: "Web User"
      type: "Human"
      trust_level: "untrusted"
  processes:
    - id: P-001
      name: "API Gateway"
      layer: "L1"
      maps_to_module: "M-001"
  data_stores:
    - id: DS-001
      name: "User Database"
      type: "PostgreSQL"
      sensitivity: "HIGH"
  data_flows:
    - id: DF-001
      from: "EI-001"
      to: "P-001"
      data: "User Request"
      encrypted: true

l1_coverage:
  total_interfaces: 45
  analyzed: 45
  coverage_percentage: 100
  interface_analysis:
    IF-001:
      analyzed: true
      data_flow_traced: true
      call_flow_mapped: true

validation_results:
  interface_coverage: 1.0
  data_flow_coverage: 1.0
  recommendation: "PROCEED_TO_PHASE_3"
```

### P3 Output: `P3_boundary_context.yaml`

```yaml
# .phase_working/data/P3_boundary_context.yaml
schema_version: "3.0.0 (20260201a)"
phase: 3
generated_at: "ISO8601"
input_ref: "P2_dfd_elements.yaml"

boundary_context:
  boundaries:
    - id: TB-001
      name: "External Trust Boundary"
      type: "network"
      scope: "internet-facing"
      components_inside: ["P-001"]
      components_outside: ["EI-001", "EI-002"]

  interfaces:
    - id: TBI-001
      boundary: "TB-001"
      direction: "inbound"
      from_zone: "external"
      to_zone: "dmz"
      data_flows: ["DF-001", "DF-002"]
      protection: ["authentication", "rate_limiting"]

  data_nodes:
    - id: DN-001
      data_store: "DS-001"
      sensitivity: "HIGH"
      data_types: ["credential", "PII"]
      boundary_location: "internal"

  cross_boundary_flows:
    - id: CBF-001
      flow: "DF-001"
      crosses: ["TB-001"]
      risk_level: "HIGH"
```

### P4 Output: `P4_security_gaps.yaml`

```yaml
# .phase_working/data/P4_security_gaps.yaml
schema_version: "3.0.0 (20260201a)"
phase: 4
generated_at: "ISO8601"
input_ref: "P3_boundary_context.yaml"

security_gaps:
  gaps:
    - id: GAP-001
      domain: "AUTHN"
      severity: "HIGH"
      description: "No MFA for admin accounts"
      affected_components: ["P-002"]
      recommendation: "Implement TOTP-based MFA"

  design_matrix:
    AUTHN:
      score: 0.7
      controls_present: ["password_auth", "jwt_tokens"]
      controls_missing: ["mfa", "passwordless"]
    AUTHZ:
      score: 0.8
      controls_present: ["rbac"]
      controls_missing: ["abac", "policy_engine"]
    # ... 16 domains total

findings:
  - id: F-P4-001
    domain: "CRYPTO"
    severity: "MEDIUM"
    observation: "Using SHA-256 for password hashing"
    expected: "bcrypt/argon2"
```

### P5 Output: `P5_threat_inventory.yaml`

```yaml
# .phase_working/data/P5_threat_inventory.yaml
schema_version: "3.0.0 (20260201a)"
phase: 5
generated_at: "ISO8601"
input_ref: "P4_security_gaps.yaml"

threat_inventory:
  threats:
    - id: T-S-P001-001
      stride_category: "S"
      element_type: "process"
      element_id: "P-001"
      title: "API Gateway Spoofing"
      description: "Attacker impersonates legitimate API client"
      cwe_refs: ["CWE-287", "CWE-290"]
      capec_refs: ["CAPEC-151"]
      attack_refs: ["T1078"]
      affected_flows: ["DF-001"]
      related_gaps: ["GAP-001"]
      initial_risk: "HIGH"
    # ... more threats

  summary:
    total: 45
    by_stride: {S: 8, T: 12, R: 5, I: 10, D: 6, E: 4}
    by_element_type: {process: 25, datastore: 12, dataflow: 8}
    by_risk: {CRITICAL: 3, HIGH: 15, MEDIUM: 20, LOW: 7}
```

### P6 Output: `P6_validated_risks.yaml`

```yaml
# .phase_working/data/P6_validated_risks.yaml
schema_version: "3.0.0 (20260201a)"
phase: 6
generated_at: "ISO8601"
input_ref: "P5_threat_inventory.yaml"

risk_summary:
  total_identified: 45      # From P5
  total_verified: 15        # Confirmed exploitable
  total_theoretical: 20     # Possible but unconfirmed
  total_pending: 5          # Need more investigation
  total_excluded: 5         # False positives or mitigated
  # MUST BALANCE: 15 + 20 + 5 + 5 = 45

risk_details:
  - id: VR-001
    threat_refs: ["T-S-P001-001"]
    validation_status: "verified"
    validation_method: "code_review"
    evidence: "No session validation in auth middleware"
    cvss_score: 8.1
    risk_level: "HIGH"

poc_details:
  - id: POC-001
    risk_ref: "VR-001"
    poc_type: "exploit_code"
    description: "JWT token forgery using weak secret"
    steps:
      - "Intercept valid JWT token"
      - "Decode and modify claims"
      - "Re-sign with guessed secret"
    success_criteria: "Gain admin access"
    estimated_effort: "LOW"

attack_paths:
  - id: AP-001
    name: "Privilege Escalation via Token Forgery"
    entry_point: "IF-001"
    target: "DS-001"
    steps:
      - {step: 1, action: "Obtain valid user JWT", component: "P-002"}
      - {step: 2, action: "Forge admin claims", component: "external"}
      - {step: 3, action: "Access admin endpoints", component: "P-003"}
    feasibility: "HIGH"
    impact: "CRITICAL"

attack_chains:
  - id: AC-001
    name: "Full Database Compromise Chain"
    paths: ["AP-001", "AP-002"]
    total_steps: 5
    complexity: "MEDIUM"
```

### P7 Output: `P7_mitigation_plan.yaml`

```yaml
# .phase_working/data/P7_mitigation_plan.yaml
schema_version: "3.0.0 (20260201a)"
phase: 7
generated_at: "ISO8601"
input_ref: "P6_validated_risks.yaml"

mitigation_plan:
  mitigations:
    - id: MIT-001
      risk_refs: ["VR-001"]
      title: "Implement Strong JWT Secret Management"
      priority: "P0"
      effort: "MEDIUM"
      control_type: "preventive"
      implementation:
        description: "Use cryptographically strong secrets with rotation"
        code_changes:
          - file: "src/auth/jwt.py"
            change_type: "modify"
            description: "Add secret rotation logic"
        config_changes:
          - file: "config/auth.yaml"
            change_type: "add"
            description: "Add JWT_SECRET_ROTATION_DAYS"
      verification:
        test_cases: ["TC-001", "TC-002"]
        acceptance_criteria: "JWT secrets rotate every 30 days"

  roadmap:
    immediate:  # P0: Fix now
      - "MIT-001"
      - "MIT-002"
    short_term:  # P1: Within 7 days
      - "MIT-003"
    medium_term:  # P2: Within 30 days
      - "MIT-004"
      - "MIT-005"
    long_term:  # P3: Backlog
      - "MIT-006"
```

### P8 Output: `P8_report_manifest.yaml`

```yaml
# .phase_working/data/P8_report_manifest.yaml
schema_version: "3.0.0 (20260201a)"
phase: 8
generated_at: "ISO8601"
input_ref: "P7_mitigation_plan.yaml"

report_manifest:
  main_report: "RISK-ASSESSMENT-REPORT.md"

  generated_reports:
    - name: "RISK-INVENTORY.md"
      source_data: "P6_validated_risks.yaml"
      status: "generated"
    - name: "MITIGATION-MEASURES.md"
      source_data: "P7_mitigation_plan.yaml"
      status: "generated"
    - name: "PENETRATION-TEST-PLAN.md"
      source_data: ["P6_validated_risks.yaml", "P7_mitigation_plan.yaml"]
      status: "generated"
    - name: "ARCHITECTURE-ANALYSIS.md"
      source_data: ["P1_project_context.yaml", "P2_dfd_elements.yaml", "P3_boundary_context.yaml"]
      status: "generated"
    - name: "DFD-DIAGRAM.md"
      source_data: "P2_dfd_elements.yaml"
      status: "generated"
    - name: "COMPLIANCE-REPORT.md"
      source_data: ["P4_security_gaps.yaml", "P7_mitigation_plan.yaml"]
      status: "generated"
    - name: "ATTACK-PATH-VALIDATION.md"
      source_data: "P6_validated_risks.yaml"
      status: "generated"

  phase_reports_published:
    - "P1-PROJECT-UNDERSTANDING.md"
    - "P2-DFD-ANALYSIS.md"
    - "P3-TRUST-BOUNDARY.md"
    - "P4-SECURITY-DESIGN-REVIEW.md"
    - "P5-STRIDE-THREATS.md"
    - "P6-RISK-VALIDATION.md"

  statistics:
    total_threats: 45
    verified_risks: 15
    mitigations_planned: 25
    compliance_score: 0.78
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

> **SESSION_ID 格式**: `{PROJECT_NAME}_{YYYYMMDD_HHMMSS}`
> 示例: `OPEN-WEBUI_20260130_143022`

---

## §7 Final Report Output

### Directory Structure

```
Risk_Assessment_Report/
│
│  ┌─ 必需报告 (4份) ────────────────────────────────────────────┐
├── {PROJECT}-RISK-ASSESSMENT-REPORT.md    ← Main report
├── {PROJECT}-RISK-INVENTORY.md            ← From P6 YAML
├── {PROJECT}-MITIGATION-MEASURES.md       ← From P7 YAML
├── {PROJECT}-PENETRATION-TEST-PLAN.md     ← From P6 YAML
│  └─────────────────────────────────────────────────────────────┘
│
│  ┌─ 扩展报告 (可选) ───────────────────────────────────────────┐
├── {PROJECT}-ARCHITECTURE-ANALYSIS.md     ← From P1-P3 YAML
├── {PROJECT}-DFD-DIAGRAM.md               ← From P2 YAML
├── {PROJECT}-COMPLIANCE-REPORT.md         ← From P4+P7 YAML
├── {PROJECT}-ATTACK-PATH-VALIDATION.md    ← From P6 YAML
│  └─────────────────────────────────────────────────────────────┘
│
│  ┌─ 阶段过程文档 (7份) ────────────────────────────────────────┐
├── P1-PROJECT-UNDERSTANDING.md            ← Human report
├── P2-DFD-ANALYSIS.md
├── P3-TRUST-BOUNDARY.md
├── P4-SECURITY-DESIGN-REVIEW.md
├── P5-STRIDE-THREATS.md
├── P6-RISK-VALIDATION.md
├── P7-MITIGATION-PLAN.md
│  └─────────────────────────────────────────────────────────────┘
│
└── .phase_working/
    │
    ├── _sessions_index.yaml               ← 多 session 索引 (可选)
    │
    └── {SESSION_ID}/                      ← Session 隔离目录
        │                                     格式: {PROJECT}_{YYYYMMDD_HHMMSS}
        │                                     示例: OPEN-WEBUI_20260130_143022
        │
        ├── _session_meta.yaml             ← Session 状态元数据
        │
        ├── data/                          ← STRUCTURED DATA (YAML)
        │   ├── P1_project_context.yaml
        │   ├── P2_dfd_elements.yaml
        │   ├── P3_boundary_context.yaml
        │   ├── P4_security_gaps.yaml
        │   ├── P5_threat_inventory.yaml
        │   ├── P6_validated_risks.yaml
        │   ├── P7_mitigation_plan.yaml
        │   └── P8_report_manifest.yaml
        │
        └── reports/                       ← WORKING REPORTS (MD)
            └── (phase reports during execution)
```

### Session ID 生成规则

```yaml
# Session ID 格式
session_id: "{PROJECT_NAME}_{YYYYMMDD_HHMMSS}"

# 示例
session_id: "OPEN-WEBUI_20260130_143022"

# 路径构造
session_dir: "Risk_Assessment_Report/.phase_working/{SESSION_ID}"
data_dir: "{session_dir}/data"
reports_dir: "{session_dir}/reports"
meta_file: "{session_dir}/_session_meta.yaml"
```

### 多 Session 支持

同一项目可以有多个评估 session：

```
.phase_working/
├── _sessions_index.yaml                   ← 可选：列出所有 sessions
├── OPEN-WEBUI_20260128_091500/           ← 历史 session
├── OPEN-WEBUI_20260129_142030/           ← 历史 session
└── OPEN-WEBUI_20260130_143022/           ← 当前 session (active)
```

---

**End of WORKFLOW.md** (~400 lines, ~5K tokens)
