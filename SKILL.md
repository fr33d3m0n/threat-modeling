<!-- Threat Modeling Skill | Version 3.0.0 (20260202a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

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

# Threat Modeling Skill v3.0.0 (20260202a)

AI-native automated software risk analysis skill. LLM-driven, Code-First approach for comprehensive security risk assessment, threat modeling, security testing, penetration testing, and compliance checking.

## Version Banner

```
════════════════════════════════════════════════════════════════════════════════
  🛡️ Threat Modeling Skill v3.0.0 (20260202a)
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
| X.Y.Z | ❌ **NO** - 需用户明确授权 | `3.0.0` → `3.0.1` or `3.1.0` |

### Current Version

- **Base Version**: `3.0.0` (frozen until user approval)
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
schema_version: "3.0.0 (20260202a)"
session_id: "OPEN-WEBUI_20260130_143022"  # {PROJECT}_{YYYYMMDD_HHMMSS}
project_name: "OPEN-WEBUI"
project_path: "/path/to/project"
started_at: "ISO8601 timestamp"
language: "en"
skill_version: "3.0.0 (20260202a)"

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

## §10 Core Execution Rules (Non-Negotiable)

> **PRINCIPLE**: 威胁建模的质量取决于执行的严谨性。以下规则不可协商。

### ❌ NO MOCK DATA

威胁分析必须基于真实代码证据，禁止假设性分析。

| 禁止行为 | 正确做法 |
|----------|----------|
| "可能存在 SQL 注入" | 提供代码位置: `src/db.py:45` 使用未参数化查询 |
| 假设性 CWE 映射 | 基于代码模式的精确映射 + KB 查询日志 |
| 凭空设计 POC | 针对真实代码路径设计可验证的 POC |

### ❌ NO SIMPLIFIED IMPLEMENTATIONS

每个阶段必须完整执行，禁止跳过或简化。

| 阶段 | 禁止简化 | 完整执行要求 |
|------|----------|-------------|
| P1 | "仅分析主要模块" | 必须发现所有入口点类型 (API/UI/System/Hidden) |
| P2 | "仅分析关键接口" | L1 Coverage 必须 100% |
| P5 | "仅生成 Top N 威胁" | 对每个 DFD 元素应用完整 STRIDE 矩阵 |
| P6 | "仅验证高危威胁" | 分层验证 (Tier 1/2/3) 覆盖所有威胁 |

### ❌ NO BYPASSING PROBLEMS

遇到问题必须诊断根因，禁止绕过或伪造进度。

| 问题类型 | 禁止行为 | 正确做法 |
|----------|----------|----------|
| 威胁无法确认 | 标记为 `excluded` | 标记为 `pending` + 记录原因 |
| KB 查询无结果 | 伪造映射 | 记录查询过程，标注"无精确匹配" |
| 复杂攻击路径 | 跳过中间步骤 | 完整追踪，必要时分解子路径 |
| 阶段验证失败 | 删除失败项 | 修复数据，重新验证 |

### Gating Protocol (每阶段必须遵循)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ① PLANNING (进入阶段前)                                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  • 明确当前阶段目标                                                          │
│  • 验证输入数据完整性 (读取 P{N-1} YAML)                                     │
│  • 确认与项目目标和安全第一性原理对齐                                         │
│  • 分解阶段内子任务，定义每个子任务的输入/输出                                │
│  • ⚠️ 如有任何不清楚之处，STOP 并澄清后再继续                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  ② EXECUTION LOOP (执行每个子任务)                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  • 使用 TodoWrite 追踪子任务状态 (pending → in_progress → completed)         │
│  • 每个子任务: 分析 → 评估 → 计划 → 实施                                     │
│  • 子任务完成后: 验证输入/输出/数据流对齐                                     │
│  • 发现问题: STOP → 修复 → 验证 → 反思 → 确认修复                            │
│  • ⚠️ 有未解决问题时，禁止继续下一个子任务                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│  ③ REFLECTION (完成阶段前)                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  • 确认所有子任务已完成并验证                                                 │
│  • 确认所有问题已修复并验证                                                   │
│  • 对齐确认: 目标 / 架构 / 数据设计 / 安全第一性原理                          │
│  • 记录反思: 什么有效 / 什么无效 / 经验教训                                   │
│  • ⚠️ 任何验证失败则 STOP，迭代直到全部通过                                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## §11 Phase Isolation Rules (BLOCKING)

> **CRITICAL**: 每个Phase是独立的执行单元，禁止合并执行！

### ⛔ FORBIDDEN Behaviors

| 禁止行为 | 原因 | 正确做法 |
|----------|------|----------|
| 在单个响应中执行多个Phase | 跳过了Entry/Exit Gate | 每个Phase独立迭代 |
| Phase N+1 在 Phase N 验证前开始 | 数据链断裂 | 等待exit 0后再继续 |
| 在一个thinking block中规划多个Phase | 上下文混淆 | 每个Phase独立THINKING |
| 跳过上游YAML读取直接分析 | 基于假设而非事实 | 必须Read → Parse → Analyze |

### ✅ REQUIRED Phase Isolation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHASE ISOLATION PROTOCOL                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Phase N Execution:                                                          │
│                                                                              │
│  1. READ: @phases/P{N}-*.md instructions                                    │
│  2. ENTRY GATE: 4-Phase Gating Protocol (THINKING → PLANNING)               │
│  3. EXECUTE: Analysis per instructions                                       │
│  4. WRITE: P{N}_*.yaml (PRIMARY) → P{N}-*.md (SECONDARY)                    │
│  5. EXIT GATE: Hook validation (exit 0 required)                            │
│  6. UPDATE: Session meta (status = "completed")                             │
│                                                                              │
│  ════════════════════════ PHASE BOUNDARY ════════════════════════           │
│                                                                              │
│  Phase N+1 Execution:                                                        │
│  (Only after Phase N EXIT GATE passes)                                      │
│                                                                              │
│  1. READ: @phases/P{N+1}-*.md instructions                                  │
│  2. ENTRY GATE: Read P{N}_*.yaml as input                                   │
│  3. ... (repeat cycle)                                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Phase Boundary Enforcement

**Entry Gate Checklist** (每个Phase开始前):
- [ ] 上一个Phase的YAML文件存在且有效？
- [ ] 上一个Phase的session_meta.status == "completed"？
- [ ] 当前Phase的instructions已加载？
- [ ] THINKING checkpoint已完成？

**Exit Gate Checklist** (每个Phase结束前):
- [ ] YAML数据文件已写入且验证通过？
- [ ] MD报告文件已写入？
- [ ] Hook validation返回exit 0？
- [ ] REFLECTION确认所有子任务完成？

⛔ **任何Gate检查失败 → STOP并修复，禁止跨越Phase边界**

---

**End of SKILL.md** (~550 lines, ~7K tokens)
