# Phase 1: Project Understanding

**Type**: Exploratory
**Executor**: Script + LLM
**Knowledge**: Security Principles

---

## Input Context

None (first phase)

## Output Context

→ P2: `project_context` {project_type, modules[], entry_points[], security_design{}}

---

## Sub-Phase Architecture

```
P1.0 (Script) → P1.1 (LLM, conditional) → P1.2 (LLM) → P1.3 (Script+LLM)
```

| Sub-Phase | Executor | Mandatory | Output |
|-----------|----------|-----------|--------|
| P1.0 | Script | Yes | project_inventory |
| P1.1 | LLM | Conditional* | yaml:doc_analysis |
| P1.2 | LLM | Yes | 3 YAML blocks |
| P1.3 | Script+LLM | Yes | validation passed |

*P1.1 required if `documentation.quality_grade != "none"`

---

## P1.0 Project Inventory (Script)

**Run first, before any manual analysis**:

```bash
python $SKILL_PATH/scripts/list_files.py <project_path> \
  --categorize --detect-type --doc-analysis --pretty
```

**Record from output**:

| Metric | Value |
|--------|-------|
| total_files | _____ |
| total_directories | _____ |
| documentation.quality_grade | high/medium/low/none |
| documentation.quality_score | 0-100 |

**Decision Gate**:

| quality_grade | Action |
|---------------|--------|
| "none" (< 10) | Skip P1.1, go to P1.2 |
| "low" (10-39) | Execute P1.1 (README only) |
| "medium" (40-69) | Execute P1.1 (standard) |
| "high" (>= 70) | Execute P1.1 (full) |

---

## P1.1 Documentation Analysis (LLM)

**Skip if**: quality_grade == "none"

**Document Priority**:
1. README.md
2. docs/ARCHITECTURE*, DESIGN*
3. docs/API*, openapi.yaml
4. CONTRIBUTING*
5. Other docs/*.md

**Output**: `yaml:doc_analysis`

```yaml:doc_analysis
schema_version: "1.0"
analyzed_at: "ISO8601"
documents_analyzed:
  - path: "README.md"
    category: "readme"
    size_bytes: 12500

project_intent:
  summary: "One-paragraph summary"
  target_users: ["developers", "enterprises"]
  key_features: ["Feature 1", "Feature 2"]

architecture_overview:
  type: "monolith|microservices|serverless|hybrid"
  frontend:
    framework: "React/Vue/Svelte"
  backend:
    framework: "FastAPI/Express/Spring"
  database:
    type: "relational/nosql/mixed"
    systems: ["PostgreSQL", "Redis"]

documented_modules:
  - name: "Authentication Module"
    description: "Handles OAuth2 and local auth"
    source: "docs/ARCHITECTURE.md"

security_mentions:
  - topic: "authentication"
    details: "OAuth2 with PKCE support"
    source: "README.md"

notes_for_analysis:
  - "Documentation mentions webhook integration not yet implemented"
```

---

## P1.2 Code Analysis (LLM)

**Core Goal**: Comprehensively understand project architecture by verifying documented claims and discovering undocumented components.

### Entry Point Types (All Must Be Scanned)

| Type | Pattern Examples | Security Sensitivity |
|------|------------------|---------------------|
| rest_api | `@app.route`, `@router.get` | HIGH |
| internal_api | Internal service calls | MEDIUM |
| graphql | `@strawberry.type` | HIGH |
| websocket | `@socketio.on` | HIGH |
| cron_jobs | `@scheduler` | MEDIUM |
| message_queue | `@celery.task` | MEDIUM |
| webhooks | `/webhook/` | HIGH |
| file_upload | `multipart` | HIGH |
| health_endpoints | `/health` | LOW |
| debug_endpoints | `/debug` | CRITICAL |

### Required Output Blocks

**Block 1**: `yaml:module_inventory`

```yaml:module_inventory
modules:
  - id: M-auth
    name: "Authentication Module"
    path: "src/auth"
    type: Authentication
    security_level: HIGH
    files: 12
    loc: 1500
    entry_types: [API, UI]
    submodules:
      - id: M-auth-handlers
        name: "Auth Handlers"
        path: "src/auth/handlers"
        files: 4
        loc: 600
```

**Block 2**: `yaml:entry_point_inventory`

```yaml:entry_point_inventory
api_entries:
  - id: EP-API-001
    path: "/api/v1/auth/login"
    methods: [POST]
    module: auth
    handler: "src/auth/handlers/login.py:45"
    auth_required: false
    exposure: EXTERNAL

ui_entries:
  - id: EP-UI-001
    type: WebForm
    path: "/login"
    component: "LoginForm"

system_entries:
  - id: EP-SYS-001
    type: CronJob
    trigger: "0 * * * *"

hidden_entries:
  - id: EP-HID-001
    path: "/health"
```

**Block 3**: `yaml:discovery_checklist`

```yaml:discovery_checklist
checklist:
  rest_api:
    scanned: true
    count: 45
    source_patterns: ["routes/*.py", "@app.route"]
    status: COMPLETED
  internal_api:
    scanned: true
    count: 8
    status: COMPLETED
  graphql:
    scanned: true
    count: 0
    status: NOT_APPLICABLE
    reason: "Project does not use GraphQL"
  websocket:
    scanned: true
    count: 2
    status: COMPLETED
  cron_jobs:
    scanned: true
    count: 3
    status: COMPLETED
  message_queue:
    scanned: true
    count: 0
    status: NOT_APPLICABLE
  webhooks:
    scanned: true
    count: 2
    status: COMPLETED
  file_upload:
    scanned: true
    count: 3
    status: COMPLETED
  health_endpoints:
    scanned: true
    count: 3
    status: COMPLETED
  debug_endpoints:
    scanned: true
    count: 1
    status: COMPLETED

summary:
  total_entry_points: 72
  coverage: "100%"
```

### Scenario Detection

| Scenario | Trigger | Extension |
|----------|---------|-----------|
| Standard Web/API | No AI/No Cloud-Native | Standard flow |
| AI/LLM Application | Model calls/RAG detected | `--all-llm` |
| Cloud-Native | AWS/Azure/GCP/K8s | `--cloud {provider}` |
| Microservices | Multi-service/Docker | Cross-service analysis |

---

## P1.3 Validation (Script)

**Run after completing P1.2**:

```bash
python $SKILL_PATH/scripts/phase_data.py --validate --phase 1 --root .
```

**Validation Rules**:

| Rule | Severity |
|------|----------|
| All code files analyzed | BLOCKING |
| All documented modules verified | BLOCKING |
| All 10 entry types scanned | WARNING |
| Entry point ID uniqueness | BLOCKING |
| Module count consistency | WARNING |

**If BLOCKING fails**: Fix issues, do not proceed
**If WARNING only**: Acknowledge and continue

---

## Report Template

```markdown
# P1: Project Understanding

## Sub-Phase Progress Tracker

| Sub-Phase | Status | Output | Notes |
|-----------|--------|--------|-------|
| P1.0 Script | □ Done | quality_grade: _____ | Script: list_files.py |
| P1.1 Doc Analysis | □ Done / □ Skipped | yaml:doc_analysis | Skip reason: _____ |
| P1.2 Code Analysis | □ Done | 3 YAML blocks | |
| P1.3 Validation | □ Done | PASSED/FAILED | |

## P1.0 Script Output Summary
- total_files: _____
- total_directories: _____
- documentation.quality_grade: _____
- documentation.has_docs_directory: _____

## P1.1 Decision
- quality_grade: `{grade}` (score: {score})
- Decision: **Execute P1.1** / **Skip P1.1**
- Reason: _____

[yaml:doc_analysis block if P1.1 executed]

## Module Inventory

[yaml:module_inventory block]

## Entry Point Inventory

[yaml:entry_point_inventory block]

## Discovery Checklist

[yaml:discovery_checklist block]

## Key Findings

1. ...
2. ...

## Security Observations

1. ...
2. ...
```

---

## Completion Checklist

Before marking Phase 1 complete:

- [ ] P1.0 script executed
- [ ] P1.1 executed OR skipped (with valid reason)
- [ ] yaml:module_inventory present
- [ ] yaml:entry_point_inventory present
- [ ] yaml:discovery_checklist present with all scanned:true
- [ ] P1.3 validation passed

---

**End of Phase 1 Instructions** (~300 lines, ~2K tokens)
