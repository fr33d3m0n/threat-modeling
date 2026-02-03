<!-- Threat Modeling Skill | Version 3.0.1 (20260203a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

---
name: threat-modeling
description: |
  AI-native automated software risk analysis skill. LLM-driven, Code-First approach for
  comprehensive security risk assessment, threat modeling, security testing, penetration
  testing, and compliance checking with 8-phase sequential workflow.

  Phases: Project Understanding → DFD Analysis → Trust Boundaries → Security Design →
          Threat Analysis → Risk Validation → Mitigation Planning → Report Generation

  Each phase requires validation (exit 0) before proceeding to next.
  Data flows via YAML files, reports are Markdown (separate concerns).

  Use when: threat model, security assessment, risk assessment, penetration test, compliance, 威胁建模, 安全评估, 渗透测试, 合规检查.

  Flags:
    --debug    Enable debug mode, publish internal YAML data files and evaluation reports
    --lang=xx  Set output language (en, zh, ja, ko, es, fr, de, pt, ru)
hooks:
  PostToolUse:
    - matcher: "Write"
      hooks:
        - type: command
          command: "./hooks/phase_end_hook.sh"  # Path relative to SKILL_PATH
          timeout: 30
---

> **Note**: All relative paths in this skill are relative to `SKILL_PATH` (the directory containing this SKILL.md file).

# Threat Modeling Skill v3.0.1 (20260203a)

AI-native automated software risk analysis skill. LLM-driven, Code-First approach for comprehensive security risk assessment, threat modeling, security testing, penetration testing, and compliance checking.

## Version Banner

```
════════════════════════════════════════════════════════════════════════════════
  🛡️ Threat Modeling Skill v3.0.1 (20260203a)
════════════════════════════════════════════════════════════════════════════════
```

## ⚠️ Version Management Rules (STRICT)

> **CRITICAL**: 未经用户明确授权，禁止变更主版本号 X.Y.Z！

### Version Format

```
vX.Y.Z (YYYYMMDDx)
 │ │ │     │    │
 │ │ │     │    └── 日期子版本 (a, b, c...) - 可自动更新
 │ │ │     └─────── 日期 (YYYYMMDD) - 可自动更新
 │ │ └───────────── Patch - 需用户确认
 │ └─────────────── Minor - 需用户确认
 └───────────────── Major - 需用户明确批准
```

### Change Rules

| Version Part | Auto-Change Allowed | Example |
|--------------|---------------------|---------|
| 日期子版本 (x) | ✅ Yes | `(20260202a)` → `(20260131b)` |
| 日期 (YYYYMMDD) | ✅ Yes | `(20260202a)` → `(20260202a)` |
| X.Y.Z | ❌ **NO** - 需用户明确授权 | `3.0.1` → `3.0.2` or `3.1.0` |

### Current Version

- **Base Version**: `3.0.1` (frozen until user approval)
- **Date Version**: `20260202a` (auto-updates allowed)

## Command Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--debug` | Publish internal YAML data files, KB queries, coverage validation, and evaluation report | OFF |
| `--lang=xx` | Set output language (en, zh, ja, ko, es, fr, de, pt, ru) | Auto-detect |

**Usage Examples**:
```bash
# Default mode - 11 deliverable files only
/threat-model @my-project

# Debug mode - all internal files published
/threat-model @my-project --debug

# Chinese output with debug
/threat-model @my-project --lang=zh --debug
```

---

## ⚠️ CRITICAL: Data vs Report Separation

> **PRINCIPLE**: Markdown 是报告（人读），YAML 是数据（机器读）。两者必须分离！

```
┌─────────────────────────────────────────────────────────────────────┐
│  DUAL OUTPUT MODEL - Each phase produces TWO files:                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. DATA FILE (.yaml) - PRIMARY                                     │
│     • Written FIRST                                                  │
│     • Structured, machine-readable                                   │
│     • Used by NEXT phase as input                                    │
│     • Path: .phase_working/{SESSION_ID}/data/P{N}_*.yaml            │
│                                                                      │
│  2. REPORT FILE (.md) - SECONDARY                                   │
│     • Written AFTER data file                                        │
│     • Human-readable, formatted                                      │
│     • For review and documentation                                   │
│     • Path: .phase_working/{SESSION_ID}/reports/P{N}-*.md           │
│                                                                      │
│  ❌ FORBIDDEN: Reading .md files for data extraction                │
│  ❌ FORBIDDEN: Embedding data as yaml blocks inside .md AS SOURCE   │
│  ✅ ALLOWED: YAML blocks in .md for schema documentation/examples   │
│  ✅ REQUIRED: Data flows via .yaml files only                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## §1 Execution Model

**Mode**: Full Assessment Only - All 8 phases executed sequentially.

```
Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► Phase 6 ──► Phase 7 ──► Phase 8
   │            │            │            │            │            │            │
   ▼            ▼            ▼            ▼            ▼            ▼            ▼
P1.yaml ──► P2.yaml ──► P3.yaml ──► P4.yaml ──► P5.yaml ──► P6.yaml ──► P7.yaml ──► P8.yaml
```

**Rules**:
1. Phases execute strictly in order (1→8)
2. Each phase reads previous phase's YAML, writes its own YAML
3. Each phase also writes a human-readable .md report
4. Validation runs on YAML files, not .md files
5. Phase 6 = Risk Validation (NOT mitigation)
6. Phase 7 = Mitigation Planning (AFTER validation)

**Phase Gate Protocol**:
```
FOR each phase N in [1..8]:
    1. Read: @phases/P{N}-*.md (instructions)
    2. Read: .phase_working/{SESSION_ID}/data/P{N-1}_*.yaml (input, except P1)
    3. Execute analysis per phase instructions
    4. Write: .phase_working/{SESSION_ID}/data/P{N}_*.yaml (PRIMARY output)
    5. Write: .phase_working/{SESSION_ID}/reports/P{N}-*.md (SECONDARY output)
    6. Hook validates YAML file
    7. IF exit != 0: Fix YAML and rewrite
    8. IF exit == 0: Update session meta, continue to N+1
```

---

## §2 Output Convention

### Output Modes

```
┌─────────────────────────────────────────────────────────────────────┐
│  OUTPUT MODES - Control what files are generated                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DEFAULT MODE (Production)                                          │
│  ─────────────────────────────────────────────────────────────────  │
│  Only user-deliverable files are published:                         │
│  ✅ 4 Required Reports (RISK-ASSESSMENT, INVENTORY, MITIGATION,    │
│                         PENETRATION-TEST-PLAN)                      │
│  ✅ 7 Phase Reports (P1-P7-*.md) for audit trail                    │
│  ❌ .phase_working/ - NOT published (kept internally)               │
│  ❌ YAML data files - NOT published                                 │
│  ❌ EVALUATION-REPORT.md - NOT published                            │
│                                                                      │
│  DEBUG MODE (--debug flag)                                          │
│  ─────────────────────────────────────────────────────────────────  │
│  All files are published including internal data:                   │
│  ✅ All default mode outputs                                        │
│  ✅ .phase_working/{SESSION_ID}/data/*.yaml - Published             │
│  ✅ P5_knowledge_base_queries.yaml - Published                      │
│  ✅ P8_coverage_validation.yaml - Published                         │
│  ✅ EVALUATION-REPORT.md - Published                                │
│                                                                      │
│  Usage: /threat-model @project --debug                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Directory Structure

**Default Mode** (11 files published):
```
{PROJECT_ROOT}/
└── Risk_Assessment_Report/
    ├── {PROJECT}-RISK-ASSESSMENT-REPORT.md    ← Required (P8)
    ├── {PROJECT}-RISK-INVENTORY.md            ← Required (P6)
    ├── {PROJECT}-MITIGATION-MEASURES.md       ← Required (P7)
    ├── {PROJECT}-PENETRATION-TEST-PLAN.md     ← Required (P6)
    ├── P1-PROJECT-UNDERSTANDING.md            ← Phase reports
    ├── P2-DFD-ANALYSIS.md
    ├── P3-TRUST-BOUNDARY.md
    ├── P4-SECURITY-DESIGN-REVIEW.md
    ├── P5-STRIDE-THREATS.md
    ├── P6-RISK-VALIDATION.md
    └── P7-MITIGATION-PLANNING.md
```

**Debug Mode** (--debug, full structure):
```
{PROJECT_ROOT}/
└── Risk_Assessment_Report/
    ├── {PROJECT}-RISK-ASSESSMENT-REPORT.md    ← Main report (from P8)
    ├── {PROJECT}-RISK-INVENTORY.md            ← From P6 YAML
    ├── {PROJECT}-MITIGATION-MEASURES.md       ← From P7 YAML
    ├── {PROJECT}-PENETRATION-TEST-PLAN.md     ← From P6 YAML
    ├── {PROJECT}-ARCHITECTURE-ANALYSIS.md     ← From P1-P3 YAML
    ├── {PROJECT}-DFD-DIAGRAM.md               ← From P2 YAML
    ├── {PROJECT}-COMPLIANCE-REPORT.md         ← From P4+P7 YAML
    ├── {PROJECT}-ATTACK-PATH-VALIDATION.md    ← From P6 YAML
    ├── P1-PROJECT-UNDERSTANDING.md            ← Published phase reports
    ├── P2-DFD-ANALYSIS.md
    ├── P3-TRUST-BOUNDARY.md
    ├── P4-SECURITY-DESIGN-REVIEW.md
    ├── P5-STRIDE-THREATS.md
    ├── P6-RISK-VALIDATION.md
    ├── EVALUATION-REPORT.md                   ← DEBUG ONLY
    └── .phase_working/                        ← DEBUG ONLY
        ├── _sessions_index.yaml               ← 多 session 索引 (可选)
        └── {SESSION_ID}/                      ← Session 隔离目录
            ├── _session_meta.yaml             ← Session state
            ├── data/                          ← STRUCTURED DATA
            │   ├── P1_project_context.yaml
            │   ├── P2_dfd_elements.yaml
            │   ├── P3_boundary_context.yaml
            │   ├── P4_security_gaps.yaml
            │   ├── P5_threat_inventory.yaml
            │   ├── P5_knowledge_base_queries.yaml  ← KB transparency
            │   ├── P6_validated_risks.yaml
            │   ├── P7_mitigation_plan.yaml
            │   ├── P8_report_manifest.yaml
            │   └── P8_coverage_validation.yaml     ← Coverage metrics
            └── reports/                       ← WORKING REPORTS
                └── (phase reports during execution)
```

### Naming Convention

- **PROJECT**: Uppercase, max 30 chars, format: `^[A-Z][A-Z0-9-]{0,29}$`
- **Example**: `OPEN-WEBUI`, `MY-PROJECT`, `STRIDE-DEMO`

### Session ID Format

- **SESSION_ID**: `{PROJECT_NAME}_{YYYYMMDD_HHMMSS}`
- **Example**: `OPEN-WEBUI_20260130_143022`

### Session Metadata

```yaml
# .phase_working/{SESSION_ID}/_session_meta.yaml
schema_version: "3.0.1 (20260203a)"
session_id: "OPEN-WEBUI_20260130_143022"  # {PROJECT}_{YYYYMMDD_HHMMSS}
project_name: "OPEN-WEBUI"
project_path: "/path/to/project"
started_at: "ISO8601 timestamp"
language: "en"
skill_version: "3.0.1 (20260203a)"

phases:
  P1:
    status: "completed"
    started_at: "2026-01-30T10:00:00Z"
    completed_at: "2026-01-30T10:30:00Z"
    data_file: "data/P1_project_context.yaml"
    report_file: "reports/P1-PROJECT-UNDERSTANDING.md"
  P2:
    status: "in_progress"
    # ...
```

---

## §3 Core Data Model

> See @assets/contracts/data-model.yaml for complete schema definitions.

### Entity Types

| Entity | ID Format | Phase | Description |
|--------|-----------|-------|-------------|
| Module | M-{Seq:03d} | P1 | Code modules/components |
| Finding | F-P{N}-{Seq:03d} | P1-P3 | Security observations (factual) |
| Gap | GAP-{Seq:03d} | P4 | Security control deficiencies |
| Threat | T-{STRIDE}-{Element}-{Seq} | P5 | STRIDE threats |
| ValidatedRisk | VR-{Seq:03d} | P6 | Verified risks |
| Mitigation | MIT-{Seq:03d} | P7 | Remediation measures |
| POC | POC-{Seq:03d} | P6 | Proof of concept |
| AttackPath | AP-{Seq:03d} | P6 | Attack vectors (single path) |
| AttackChain | AC-{Seq:03d} | P6 | Multi-step attack sequences |
| TestCase | TC-{Seq:03d} | P8 | Penetration test cases |

### Finding vs Gap Semantic Boundary

- **Finding (F-P{N}-xxx)**: A factual **observation** from phases 1-3 that MAY have security implications. Findings are objective facts about architecture, data flows, or boundaries. Example: "API endpoint uses HTTP instead of HTTPS"

- **Gap (GAP-xxx)**: A **security control deficiency** identified in P4 after analyzing findings against security domains. Gaps represent missing or inadequate controls. Example: "Missing TLS enforcement (NETWORK domain)"

**Transition Rule**: Findings from P1-P3 feed into P4 analysis. P4 evaluates findings against 16 security domains and produces Gaps where controls are deficient.

### DFD Element IDs

| Element Type | Prefix | Format | Example |
|--------------|--------|--------|---------|
| External Interactor | EI | EI-{NNN} | EI-001 |
| Process | P | P-{NNN} | P-001 |
| Data Store | DS | DS-{NNN} | DS-001 |
| Data Flow | DF | DF-{NNN} | DF-001 |
| Trust Boundary | TB | TB-{NNN} | TB-001 |

### Count Conservation (P5→P6 Threat Accounting)

```
P5.threat_count = P6.verified + P6.theoretical + P6.pending + P6.excluded
```

All threats from P5 must be accounted for in P6 (no threat loss).

**Semantic Distinction**:
- **Count Conservation**: P5→P6 threat accounting (threats flow from P5 to P6 dispositions)
- **Element Coverage Verification**: P2→P5 element coverage (every DFD element has STRIDE analysis)

---

## §4 Security Knowledge Architecture

> See @knowledge/ for complete reference materials (26+ MB, 113 files).

### Three Knowledge Sets

1. **Security Control Set** (What to do)
   - 16 Security Domains (AUTHN, AUTHZ, INPUT, etc.)
   - Control Sets (18 files, 107 controls)
   - OWASP References (74 items)
   - Compliance Frameworks (14 frameworks)

2. **Threat Pattern Set** (What to know)
   - CWE Weaknesses (974)
   - CAPEC Attack Patterns (615)
   - ATT&CK Techniques (835)
   - CVE/KEV Vulnerabilities (323K+)

3. **Verification Set** (How to test)
   - WSTG Tests (121)
   - MASTG Tests (206)
   - ASVS Requirements (345)

### Security Principles (11)

| Code | Principle | Definition |
|------|-----------|------------|
| DID | Defense in Depth | Multiple independent security controls |
| LP | Least Privilege | Minimum permissions required |
| ZT | Zero Trust | Never trust, always verify |
| FS | Fail Secure | Default to secure state on error |
| SOD | Separation of Duties | Critical ops require multiple parties |
| SBD | Secure by Default | Default config is secure |
| CM | Complete Mediation | Every access verified |
| EOM | Economy of Mechanism | Simple, auditable mechanisms |
| OD | Open Design | Security not dependent on secrecy |
| IV | Input Validation | All input validated |
| LA | Least Agency | Limit AI agent autonomy |

### STRIDE Categories

| STRIDE | Name | CWEs | CAPEC |
|--------|------|------|-------|
| S | Spoofing | CWE-287, 290, 307 | CAPEC-151, 194, 600 |
| T | Tampering | CWE-20, 77, 78, 89 | CAPEC-66, 88, 248 |
| R | Repudiation | CWE-117, 223, 778 | CAPEC-93 |
| I | Information Disclosure | CWE-200, 209, 311 | CAPEC-116, 157 |
| D | Denial of Service | CWE-400, 770, 918 | CAPEC-125, 227 |
| E | Elevation of Privilege | CWE-269, 284, 862 | CAPEC-122, 233 |

---

## §5 Knowledge Base Queries

### kb Wrapper Usage

```bash
# Get skill path
SKILL_PATH=$(bash skill_path.sh)

# STRIDE queries
$SKILL_PATH/kb --stride spoofing
$SKILL_PATH/kb --stride-controls S

# CWE queries
$SKILL_PATH/kb --cwe CWE-89
$SKILL_PATH/kb --full-chain CWE-89

# Attack patterns
$SKILL_PATH/kb --capec CAPEC-89
$SKILL_PATH/kb --attack-technique T1078

# Verification tests
$SKILL_PATH/kb --stride-tests S
$SKILL_PATH/kb --wstg-category ATHN

# LLM/AI extensions
$SKILL_PATH/kb --all-llm
$SKILL_PATH/kb --ai-component
```

---

## §6 Language Adaptation

Output language follows context language unless `--lang=xx` specified.

| Context | File Names | Content |
|---------|------------|---------|
| Chinese | P1-项目理解.md | 中文 |
| English | P1-PROJECT-UNDERSTANDING.md | English |

Supported: en, zh, ja, ko, es, fr, de, pt, ru

---

## §7 Progressive Context Loading

This skill uses progressive disclosure:

1. **Always Loaded**: This file (SKILL.md) - ~5K tokens
2. **Session Start**: @WORKFLOW.md - ~3K tokens
3. **Per Phase**: @phases/P{N}-*.md - ~2K tokens each

Total per-phase context: ~10K tokens (vs 30K monolithic)

**Loading Pattern**:
```
Session Start:
  1. Load SKILL.md (global rules)
  2. Load WORKFLOW.md (orchestration)
  3. Create 8 phase todos

Per Phase:
  1. Read @phases/P{N}-*.md
  2. Execute phase instructions
  3. Write to .phase_working/{SESSION_ID}/reports/P{N}-*.md
  4. Hook validates and extracts data
```

---

## §8 Reference Files

| Path | Purpose |
|------|---------|
| @WORKFLOW.md | Orchestration contracts, phase gates |
| @phases/P{1-8}-*.md | Phase-specific instructions |
| @assets/contracts/data-model.yaml | Entity schemas |
| @knowledge/security-design.yaml | 16 security domains |
| @knowledge/security-principles.yaml | 11 security principles |
| @knowledge/sast-rules.yaml | SAST tool configs and STRIDE mappings |
| @scripts/module_discovery.py | P1 three-layer module discovery |
| @scripts/phase_data.py | Phase validation and extraction |
| @scripts/unified_kb_query.py | Knowledge base queries |
| @skill_path.sh | SKILL_PATH resolution helper |
| @hooks/phase_end_hook.sh | PostToolUse automation |

---

## §9 Quick Start

```bash
# 1. Start new session (default mode - 11 deliverable files)
/threat-model @my-project

# 2. With debug mode (all internal files published)
/threat-model @my-project --debug

# 3. Session execution:
#    - Claude loads SKILL.md + WORKFLOW.md automatically
#    - For each phase N (1-8): Read → Execute → Write → Validate
#    - Generate final reports in Risk_Assessment_Report/
```

### Output Summary

| Mode | Files Published | Use Case |
|------|-----------------|----------|
| Default | 11 (4 required + 7 phase reports) | Production delivery |
| `--debug` | 11 + YAML data + evaluation | Development, audit |

---

## §10 Core Execution Constraints (Invariants)

> **PRINCIPLE**: 威胁建模的质量取决于执行的严谨性。以下约束不可违反。

### Three Absolute Prohibitions

| 约束 | 描述 | 违反后果 |
|------|------|----------|
| ❌ NO MOCK DATA | 所有分析必须基于真实代码证据 | 分析结果无效 |
| ❌ NO SIMPLIFIED IMPLEMENTATIONS | 每个阶段必须完整执行 | 覆盖率不达标 |
| ❌ NO BYPASSING PROBLEMS | 遇到问题必须诊断根因 | 数据链断裂 |

### Phase Execution Invariant

```
∀ Phase N ∈ [1..8]:
  - Input: P{N-1}_*.yaml (except P1)
  - Output: P{N}_*.yaml (PRIMARY) + P{N}-*.md (SECONDARY)
  - Gate: Hook validation must return exit 0
  - Transition: Only proceed to N+1 after gate passes
```

> **Execution Protocol Details**: See WORKFLOW.md §2 Phase Execution Protocol

---

## §11 Phase Isolation Constraints

> **INVARIANT**: 每个 Phase 是独立的执行单元，FSM 状态转换必须严格顺序。

### Forbidden State Transitions

| 非法转换 | 原因 |
|----------|------|
| Pn → Pn+2 (跳过) | 违反 FSM 顺序不变性 (S1) |
| Pn → Pn+1 (未验证) | 违反数据契约完整性 (S2) |
| 多 Phase 并行执行 | 数据依赖无法满足 |

### FSM State Machine Reference

```
States: {INIT, P1, P2, P3, P4, P5, P6, P7, P8, DONE, ERROR}
Transitions: δ(Pn, pn_complete) → P(n+1) where n ∈ {1..7}
Accepting: {DONE}
```

> **Complete FSM Specification**: See WORKFLOW.md §1.5 Workflow State Machine
> **Formal Properties**: See docs/SKILL-ARCHITECTURE-DESIGN.md §0.2

---

**End of SKILL.md** (~470 lines, ~5.5K tokens)
