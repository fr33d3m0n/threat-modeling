<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

---
name: threat-modeling
description: |
  Code-first automated threat modeling toolkit. STRICT 8-PHASE WORKFLOW - DO NOT MODIFY.

  **MANDATORY: Create exactly 8 TodoWrite items with these EXACT names:**
  - Phase 1: Project Understanding (项目理解)
  - Phase 2: Call Flow & DFD Analysis (数据流分析)
  - Phase 3: Trust Boundary Evaluation (信任边界)
  - Phase 4: Security Design Review (安全设计评审)
  - Phase 5: STRIDE Threat Analysis (STRIDE分析)
  - Phase 6: Risk Validation (风险验证) ← NOT mitigation!
  - Phase 7: Mitigation Planning (缓解措施) ← AFTER validation!
  - Phase 8: Report Generation (报告生成) ← Output to Risk_Assessment_Report/

  **MANDATORY OUTPUT (Phase 8):**
  - Directory: `{PROJECT_ROOT}/Risk_Assessment_Report/`
  - Main report: `{PROJECT}-RISK-ASSESSMENT-REPORT.md` (PROJECT=UPPERCASE)
  - Required: 4 reports + 6 phase docs (P1-P6)
  - ❌ FORBIDDEN: `THREAT-MODEL-REPORT.md` or reports in project root

  Use when: threat model, STRIDE, DFD, security assessment, 威胁建模, 安全评估.
---

# Code-First Deep Risk Analysis v2.0

Code-first automated deep threat modeling with comprehensive security chain analysis.

## Execution Mode

**Full Assessment Only** - All 8 phases executed sequentially with maximum depth.

```
Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► Phase 6 ──► Phase 7 ──► Phase 8
Project     Call Flow    Trust      Security    STRIDE      Risk        Mitigation   Report
Understanding  DFD      Boundaries   Design     Analysis   Validation
```

**Strict Workflow Rules**:
1. Phases execute strictly in order (1→2→3→4→5→6→7→8)
2. Each phase output passes to next phase as input
3. Summary and reflection after each phase before proceeding
4. No skipping, reordering, or parallel execution of phases
5. Multi-risk analysis within phases can use parallel sub-agents

### Phase Todo Creation — CRITICAL REQUIREMENT

> ⚠️ **STOP AND READ**: Before ANY analysis, you MUST create EXACTLY 8 todo items.
> DO NOT proceed until you have created all 8 phases as separate todo items.
> DO NOT modify phase names or descriptions. Copy EXACTLY as shown below.

**MANDATORY TodoWrite Call (copy exactly, do not modify)**:

```json
[
  {"content": "Phase 1: Project Understanding", "status": "pending", "activeForm": "分析项目架构和技术栈"},
  {"content": "Phase 2: Call Flow & DFD Analysis", "status": "pending", "activeForm": "构建数据流图"},
  {"content": "Phase 3: Trust Boundary Evaluation", "status": "pending", "activeForm": "识别信任边界"},
  {"content": "Phase 4: Security Design Review", "status": "pending", "activeForm": "评估安全设计"},
  {"content": "Phase 5: STRIDE Threat Analysis", "status": "pending", "activeForm": "执行STRIDE分析"},
  {"content": "Phase 6: Risk Validation", "status": "pending", "activeForm": "验证风险和攻击路径"},
  {"content": "Phase 7: Mitigation Planning", "status": "pending", "activeForm": "制定缓解措施"},
  {"content": "Phase 8: Report Generation", "status": "pending", "activeForm": "生成威胁建模报告"}
]
```

**VIOLATIONS (will cause incorrect analysis)**:
- ❌ Creating fewer than 8 phases
- ❌ Combining phases (e.g., "Phase 2-7: Complete analysis")
- ❌ Renaming phases (e.g., "Phase 6: 缓解措施" instead of "Phase 6: Risk Validation")
- ❌ Skipping Phase 6 (Risk Validation) or Phase 7 (Mitigation Planning)
- ❌ Starting analysis before creating all 8 todo items

**CORRECT execution order**:
1. Phase 6 = Risk Validation (验证风险和攻击路径) — NOT mitigation
2. Phase 7 = Mitigation Planning (制定缓解措施) — comes AFTER validation
3. Phase 8 = Report Generation (生成报告) — final phase, MUST exist

## Report Output Convention

### Output Directory Structure

```
{PROJECT_ROOT}/
└── Risk_Assessment_Report/              ← 最终报告输出目录
    │
    │  ┌─ 必需报告 (4份) ──────────────────────────────────────────────┐
    ├── {PROJECT}-RISK-ASSESSMENT-REPORT.md    ← 风险评估报告 (主报告)
    ├── {PROJECT}-RISK-INVENTORY.md            ← 风险清单
    ├── {PROJECT}-MITIGATION-MEASURES.md       ← 缓解措施
    ├── {PROJECT}-PENETRATION-TEST-PLAN.md     ← 渗透测试方案 ✨ NEW
    │  └──────────────────────────────────────────────────────────────┘
    │
    │  ┌─ 阶段过程文档 (从.phase_working复制，保留英文名) ──────────────┐
    ├── P1-PROJECT-UNDERSTANDING.md            ← Phase 1 项目理解
    ├── P2-DFD-ANALYSIS.md                     ← Phase 2 DFD分析
    ├── P3-TRUST-BOUNDARY.md                   ← Phase 3 信任边界
    ├── P4-SECURITY-DESIGN-REVIEW.md           ← Phase 4 安全设计评估
    ├── P5-STRIDE-THREATS.md                   ← Phase 5 STRIDE威胁分析
    ├── P6-RISK-VALIDATION.md                  ← Phase 6 风险验证
    │  └──────────────────────────────────────────────────────────────┘
    │
    └── .phase_working/                        ← 阶段产物工作目录 (隐藏)
        ├── _session_meta.yaml                 ← 会话元数据
        ├── P1-PROJECT-UNDERSTANDING.md        ← Phase 1 工作文档
        ├── P2-DFD-ANALYSIS.md                 ← Phase 2 工作文档
        ├── P3-TRUST-BOUNDARY.md               ← Phase 3 工作文档
        ├── P4-SECURITY-DESIGN-REVIEW.md       ← Phase 4 工作文档
        ├── P5-STRIDE-THREATS.md               ← Phase 5 工作文档
        ├── P6-RISK-VALIDATION.md              ← Phase 6 工作文档
        └── P7-MITIGATION-PLAN.md              ← Phase 7 工作文档
```

### File Naming Convention

**Format**: `{PROJECT}-{REPORT_TYPE}.md`

- **PROJECT**: 从项目名提取，转大写，最多30字符
  - 格式: `^[A-Z][A-Z0-9-]{0,29}$`
  - 示例: `OPEN-WEBUI`, `MY-PROJECT`, `STRIDE-DEMO`
- **REPORT_TYPE**: 标准报告类型 (大写)

| 报告类型 | 必需条件 | 文件名示例 |
|---------|---------|-----------|
| 风险评估报告 (主报告) | ✅ 始终 | `OPEN-WEBUI-RISK-ASSESSMENT-REPORT.md` |
| 风险清单 | ✅ 始终 | `OPEN-WEBUI-RISK-INVENTORY.md` |
| 缓解措施 | ✅ 始终 | `OPEN-WEBUI-MITIGATION-MEASURES.md` |
| 渗透测试方案 | ✅ 始终 | `OPEN-WEBUI-PENETRATION-TEST-PLAN.md` |
| 架构分析 | ⚪ 可选 | `OPEN-WEBUI-ARCHITECTURE-ANALYSIS.md` |
| DFD图 | ⚪ 可选 | `OPEN-WEBUI-DFD-DIAGRAM.md` |
| 合规映射 | ⚪ 可选 | `OPEN-WEBUI-COMPLIANCE-MAPPING.md` |
| 攻击路径 | ⚪ 可选 | `OPEN-WEBUI-ATTACK-PATHS.md` |
| 执行摘要 | ⚪ 可选 | `OPEN-WEBUI-EXECUTIVE-SUMMARY.md` |

**图例**: ✅ 必需 | ⚪ 可选

### Phase Output Persistence

**每阶段完成时**:
1. 将阶段输出写入 `.phase_working/P{N}-*.md`
2. 更新 `_session_meta.yaml` 的 `phases_completed`

**会话元数据** (`_session_meta.yaml`):
```yaml
session_id: "20260103-120000"
project_name: "OPEN-WEBUI"
project_path: "/path/to/project"
started_at: "2026-01-03T12:00:00+08:00"
phases_completed: [1, 2, 3]  # 已完成的阶段
current_phase: 4
skill_version: "2.1.0"
```

### Session Recovery

新会话启动时检查 `.phase_working/`:
- 存在且 `project_name` 匹配 → 提示: "继续上次会话" 或 "覆盖重新开始"
- 存在但 `project_name` 不同 → 清空目录，开始新会话
- 不存在 → 创建目录，开始新会话

> **详细规范**: 见 `WORKFLOW.md` Phase 8 部分
> **示例**: 见 `EXAMPLES.md`

## Language Adaptation Rules

**原则**: 输出语言跟随上下文语言，除非显式指定。

### 语言检测逻辑

```
用户指令语言 → 输出语言
├── 中文指令/上下文 → 中文文件名 + 中文内容
├── 英文指令/上下文 → 英文文件名 + 英文内容
├── 其他语言 → 跟随该语言
└── --lang=xx 显式指定 → 覆盖自动检测
```

### 影响范围

| 元素 | 语言自适应 | 示例 (中文上下文) | 示例 (英文上下文) |
|------|-----------|------------------|------------------|
| 报告文件名 | ✅ | `项目-风险评估报告.md` | `PROJECT-RISK-ASSESSMENT-REPORT.md` |
| 阶段产物文件名 | ✅ | `P1-项目理解.md` | `P1-PROJECT-UNDERSTANDING.md` |
| 报告内容 | ✅ | 中文正文 | English content |
| 目录名 | ✅ | `风险评估报告/` | `Risk_Assessment_Report/` |
| 模板占位符 | ❌ | 保持英文 (内部使用) | 保持英文 |

### 显式语言指定

```bash
# 强制英文输出 (即使上下文是中文)
--lang=en

# 强制中文输出 (即使上下文是英文)
--lang=zh

# 支持的语言代码: en, zh, ja, ko, es, fr, de, pt, ru
```

### 实现方式

- **模板**: 保持单一英文模板 (assets/templates/*.template.md)
- **转换**: LLM 根据上下文语言实时翻译输出
- **文件名映射**: 见下表

#### 文件名语言映射表

| English (Default) | 中文 | Français | Español |
|-------------------|------|----------|---------|
| `RISK-ASSESSMENT-REPORT` | `风险评估报告` | `RAPPORT-EVALUATION-RISQUES` | `INFORME-EVALUACION-RIESGOS` |
| `RISK-INVENTORY` | `风险清单` | `INVENTAIRE-RISQUES` | `INVENTARIO-RIESGOS` |
| `MITIGATION-MEASURES` | `缓解措施` | `MESURES-ATTENUATION` | `MEDIDAS-MITIGACION` |
| `PENETRATION-TEST-PLAN` | `渗透测试方案` | `PLAN-TEST-PENETRATION` | `PLAN-PRUEBA-PENETRACION` |
| `P1-PROJECT-UNDERSTANDING` | `P1-项目理解` | `P1-COMPREHENSION-PROJET` | `P1-COMPRENSION-PROYECTO` |
| `P2-DFD-ANALYSIS` | `P2-数据流分析` | `P2-ANALYSE-DFD` | `P2-ANALISIS-DFD` |
| `P3-TRUST-BOUNDARY` | `P3-信任边界` | `P3-LIMITE-CONFIANCE` | `P3-LIMITE-CONFIANZA` |
| `P4-SECURITY-DESIGN-REVIEW` | `P4-安全设计评审` | `P4-REVUE-CONCEPTION-SECURITE` | `P4-REVISION-DISENO-SEGURIDAD` |
| `P5-STRIDE-THREATS` | `P5-STRIDE威胁分析` | `P5-MENACES-STRIDE` | `P5-AMENAZAS-STRIDE` |
| `P6-RISK-VALIDATION` | `P6-风险验证` | `P6-VALIDATION-RISQUES` | `P6-VALIDACION-RIESGOS` |
| `Risk_Assessment_Report/` | `风险评估报告/` | `Rapport_Evaluation_Risques/` | `Informe_Evaluacion_Riesgos/` |

> **注意**: 技术术语 (STRIDE, DFD, CWE, CAPEC, ATT&CK) 保持英文不翻译。

## Skill Path Resolution

**Issue**: Scripts use relative paths `scripts/unified_kb_query.py`, but Claude may work in project root.

**Solution**: Resolve Skill installation path before executing scripts.

### Path Detection Algorithm

```
Priority Order:
1. $SKILL_PATH environment variable (explicit override)
2. Script self-location (when running from skill directory)
3. Project-local paths (multi-platform):
   - .claude/skills/{threat-modeling|skill-threat-modeling}/
   - .agents/skills/{name}/     (Portable/XDG standard)
   - .qwen/agents/{name}/       (Qwen Code)
   - .codex/skills/{name}/      (OpenAI Codex)
   - .github/skills/{name}/     (GitHub Copilot)
   - .goose/skills/{name}/      (Goose)
4. Global paths (multi-platform):
   - ~/.claude/skills/{name}/
   - ~/.config/agents/skills/{name}/   (XDG Portable)
   - ~/.qwen/agents/{name}/
   - ~/.codex/skills/{name}/
   - ~/.config/goose/skills/{name}/
```

**Supported Directory Names**: `threat-modeling`, `skill-threat-modeling` (both work)

### Claude Invocation Pattern

**Step 1**: Detect and cache SKILL_PATH at session start:
```bash
# Use the skill_path.sh helper (recommended - supports all platforms)
SKILL_PATH=$(bash skill_path.sh)

# Or set environment variable explicitly
export SKILL_PATH=/path/to/skill-threat-modeling
```

**Step 2**: Execute scripts using detected path:
```bash
# Standard invocation pattern
python "$SKILL_PATH/scripts/unified_kb_query.py" --stride spoofing

# Or cd to skill directory
cd "$SKILL_PATH" && python scripts/unified_kb_query.py --stride spoofing
```

### Shortcut 1: kb wrapper (Recommended)

Skill includes `kb` wrapper script for invocation from any directory:
```bash
# Use absolute path to invoke kb wrapper
$SKILL_PATH/kb --stride spoofing
$SKILL_PATH/kb --full-chain CWE-89
$SKILL_PATH/kb --all-llm

# Or add to PATH
export PATH="$SKILL_PATH:$PATH"
kb --stride spoofing
```

### Shortcut 2: skill_path.sh

Get skill path for other operations:
```bash
# Get skill path
SKILL_PATH=$(bash skill_path.sh)

# One-liner invocation
python "$(bash skill_path.sh)/scripts/unified_kb_query.py" --stride spoofing
```

### Development Mode

Use source path directly during development:
```bash
# Development path (non-installed mode)
cd /path/to/threat-modeling
python scripts/unified_kb_query.py --stride spoofing
```

### Script Invocation Convention

All `python scripts/unified_kb_query.py ...` examples in this document assume:
1. `cd $SKILL_PATH` has been executed, or
2. Use `$SKILL_PATH/kb ...` as replacement

**Claude should detect SKILL_PATH at session start and use `kb` wrapper or cd mode.**

---

## Security Knowledge Architecture

### Three Knowledge Sets

The security knowledge system consists of three complementary sets:

```
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                              Security Knowledge Architecture                                   │
├───────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                │
│                       ┌───────────────────────────────────────────┐                           │
│                       │         Security Principles               │                           │
│                       │    (Foundation - Guides All Phases)       │                           │
│                       │  DID │ LP │ ZT │ FS │ SOD │ SBD │ CM │ EOM │ OD │ IV │ LA            │
│                       └───────────────────────────────────────────┘                           │
│                                           │                                                    │
│                 ┌─────────────────────────┴─────────────────────────┐                         │
│                 │                                                    │                         │
│                 ▼                                                    ▼                         │
│  ┌─────────────────────────────────────┐      ┌─────────────────────────────────────┐        │
│  │      Security Control Set          │      │      Threat Pattern Set             │        │
│  │      (What to do & How to do)      │      │      (What to know & Validate)      │        │
│  ├─────────────────────────────────────┤      ├─────────────────────────────────────┤        │
│  │  Security Domains (16)              │      │  CWE Weakness Types (974)           │        │
│  │      │                              │      │      │                              │        │
│  │      ▼                              │      │      ▼                              │        │
│  │  Control Sets (18 files, 107)       │      │  CAPEC Attack Patterns (615)        │        │
│  │      │                              │      │      │                              │        │
│  │      ▼                              │      │      ▼                              │        │
│  │  OWASP References (74)              │      │  ATT&CK Techniques (835)            │        │
│  │      │                              │      │      │                              │        │
│  │      ▼                              │      │      ▼                              │        │
│  │  Compliance Frameworks (14)         │      │  CVE/KEV Vulnerabilities (323K+)    │        │
│  └──────────────┬──────────────────────┘      └──────────────┬──────────────────────┘        │
│                 │                                             │                               │
│                 │      ┌─────────────────────────────┐        │                               │
│                 │      │    Verification Set         │        │                               │
│                 │      │  (How to verify & test)     │        │                               │
│                 └─────▶│                             │◀───────┘                               │
│                        │  WSTG Tests (121)           │                                        │
│                        │  MASTG Tests (206)          │                                        │
│                        │  ASVS Requirements (345)    │                                        │
│                        └─────────────────────────────┘                                        │
│                                     │                                                          │
│                                     ▼                                                          │
│                        Used in: Phase 6 / Phase 7 / Phase 8                                   │
│                                                                                                │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Security Principles (11)

Core security principles that guide all security design decisions across all 8 phases.

| Code | Principle | Definition |
|------|-----------|------------|
| **DID** | Defense in Depth | Multiple independent security controls; single point failure doesn't compromise system |
| **LP** | Least Privilege | Grant only minimum permissions required to complete task |
| **ZT** | Zero Trust | Never trust, always verify; assume network is compromised |
| **FS** | Fail Secure | Default to most secure state on error |
| **SOD** | Separation of Duties | Critical operations require multiple parties; prevent single-person abuse |
| **SBD** | Secure by Default | Default configuration is secure; user must actively reduce security |
| **CM** | Complete Mediation | Every access must be verified; no bypass paths |
| **EOM** | Economy of Mechanism | Security mechanisms should be simple and auditable; complexity is security's enemy |
| **OD** | Open Design | Security doesn't depend on algorithm or design secrecy |
| **IV** | Input Validation | All input must be validated before processing; default deny |
| **LA** | Least Agency | Limit AI agent autonomy, tool access, and decision scope to minimum required |

**Phase References**:
- Phase 1: DID, LP, ZT, LA (architecture assessment, agent scope)
- Phase 2: CM, IV, ZT (data flow security)
- Phase 3: ZT, SOD, LP, LA (trust boundaries, agent boundaries)
- Phase 4: All 11 principles (security function completeness)

> Detailed definitions in `assets/knowledge/security-principles.yaml`

### Security Control Set

Defines "what to do" and "how to do it" from a defensive perspective.

```
Security Domains ──▶ Control Sets ──▶ OWASP References ──▶ Compliance Frameworks
       │                  │                  │                      │
   security-         control-set-       reference-set-          YAML + SQLite
   design.yaml         *.md               *.md              (compliance tables)
```

**Security Domains (16 total)**:

| Seq | Code | Name | STRIDE | Description |
|-----|------|------|--------|-------------|
| 01 | AUTHN | Authentication & Session | S | Identity verification and session lifecycle |
| 02 | AUTHZ | Authorization & Access Control | E | Access permission enforcement |
| 03 | INPUT | Input Validation | T | External input validation and sanitization |
| 04 | OUTPUT | Output Encoding | T,I | Context-aware output encoding |
| 05 | CLIENT | Client-Side Security | S,T,I | Browser and client-side security |
| 06 | CRYPTO | Cryptography & Transport | I | Data encryption in transit and at rest |
| 07 | LOG | Logging & Monitoring | R | Security event logging and audit |
| 08 | ERROR | Error Handling | I | Secure error handling and information control |
| 09 | API | API & Service Security | S,T,I,D,E | API endpoint and service communication security |
| 10 | DATA | Data Protection | I | Sensitive data and credential protection |
| ext-11 | INFRA | Infrastructure Security | - | Container and orchestration security |
| ext-12 | SUPPLY | Supply Chain Security | - | Dependency and pipeline security |
| ext-13 | AI | AI/LLM Security | - | LLM-specific threats (OWASP LLM Top 10) |
| ext-14 | MOBILE | Mobile Security | - | Mobile app security |
| ext-15 | CLOUD | Cloud Security | - | Cloud-native security controls |
| ext-16 | AGENT | Agentic Security | S,T,R,I,D,E | AI Agent security (OWASP Agentic Top 10) |

### Threat Pattern Set

Defines "what to know" and "what to validate" from an offensive perspective.

```
CWE Weaknesses ──▶ CAPEC Patterns ──▶ ATT&CK Techniques ──▶ CVE/KEV Vulnerabilities
       │                 │                   │                       │
   SQLite:cwe       SQLite:capec      SQLite:attack_*         SQLite:cve + API
   (974 entries)    (615 entries)     (835 entries)           (323K+ entries)
```

**STRIDE to CWE Mapping**:

| STRIDE | Primary CWEs | Attack Patterns |
|--------|--------------|-----------------|
| S (Spoofing) | CWE-287, 290, 307 | CAPEC-151, 194, 600 |
| T (Tampering) | CWE-20, 77, 78, 89 | CAPEC-66, 88, 248 |
| R (Repudiation) | CWE-117, 223, 778 | CAPEC-93 |
| I (Information Disclosure) | CWE-200, 209, 311 | CAPEC-116, 157 |
| D (Denial of Service) | CWE-400, 770, 918 | CAPEC-125, 227 |
| E (Elevation of Privilege) | CWE-269, 284, 862 | CAPEC-122, 233 |

### Verification Set (Cross-Cutting)

Bridges Security Control Set and Threat Pattern Set, providing test procedures for Phase 6/7/8.

| Component | Tests/Requirements | Usage |
|-----------|-------------------|-------|
| WSTG (Web Security Testing Guide) | 121 tests | Phase 6: Risk validation |
| MASTG (Mobile App Security Testing Guide) | 206 tests | Phase 6: Mobile risk validation |
| ASVS (Application Security Verification Standard) | 345 requirements | Phase 7-8: Mitigation & compliance |

**STRIDE to Verification Mapping**:

| STRIDE | Verification Categories | Test Count |
|--------|------------------------|------------|
| S (Spoofing) | WSTG-ATHN/IDNT/SESS, MASTG-AUTH, ASVS-V6/V7/V9/V10 | 240 |
| T (Tampering) | WSTG-INPV/CONF/CLNT, MASTG-PLATFORM/RESILIENCE, ASVS-V1/V2/V3 | 402 |
| R (Repudiation) | WSTG-BUSL, ASVS-V7/V16 | 46 |
| I (Information Disclosure) | WSTG-INFO/ERRH/CRYP, MASTG-STORAGE/NETWORK, ASVS-V11/V12/V14 | 442 |
| D (Denial of Service) | WSTG-BUSL/APIT, MASTG-RESILIENCE | 49 |
| E (Elevation of Privilege) | WSTG-AUTHZ, MASTG-PLATFORM, ASVS-V8 | 90 |
| **Total** | All verification tests mapped to STRIDE | **1,269** |

---

## 8-Phase Workflow Overview

| Phase | Name | Type | Knowledge Sets Used | Key Output |
|-------|------|------|---------------------|------------|
| **1** | Project Understanding | Exploratory | Security Principles | findings_1: project_context |
| **2** | Call Flow & DFD | Constructive | Principles + security-design.yaml | findings_2: dfd_elements |
| **3** | Trust Boundaries | Evaluative | Principles + security-design.yaml | findings_3: boundary_context |
| **4** | Security Design | Evaluative | Control Sets + References | findings_4: security_gaps |
| **5** | STRIDE Analysis | Enumerative | CWE → CAPEC (Threat Pattern Set) | findings_5: threat_inventory |
| **6** | Risk Validation | Verification | Threat Pattern Set + Verification Set | validated_risks |
| **7** | Mitigation | Prescriptive | Control Sets + CWE Mitigations + ASVS | mitigation_plan |
| **8** | Report | Comprehensive | All outputs + Compliance + ASVS | RISK-ASSESSMENT-REPORT.md |

---

## Core Data Model (核心数据模型) ⚠️ CRITICAL

> **Design Principle**: 从数据流动和转换的本质出发，定义清晰的实体、关系和转换规则

### Entity Definitions (实体定义)

```
┌─────────────────────────────────────────────────────────────────┐
│                      Core Entity Model                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Finding (发现)                                          │   │
│  │  ─────────────────                                       │   │
│  │  来源: Phase 1-4                                         │   │
│  │  ID: F-P{N}-{Seq}  例: F-P1-001, F-P4-003               │   │
│  │  性质: 安全相关的观察、缺陷、风险点                         │   │
│  │  数量: 通常 10-30 个                                      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼ (输入 Phase 5)                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Threat (威胁)                                           │   │
│  │  ─────────────────                                       │   │
│  │  来源: Phase 5 STRIDE 分析                               │   │
│  │  ID: T-{STRIDE}-{ElementID}-{Seq}  例: T-T-P13-002       │   │
│  │  性质: 针对 DFD 元素的潜在攻击向量                         │   │
│  │  数量: 通常 50-200 个 (每元素多个)                         │   │
│  │  状态: identified (已识别)                                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼ (验证 Phase 6)                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  ValidatedRisk (验证风险)                                │   │
│  │  ─────────────────                                       │   │
│  │  来源: Phase 6 风险验证                                   │   │
│  │  ID: VR-{Seq}  例: VR-001                                │   │
│  │  性质: 经过验证的、可利用的风险                            │   │
│  │  数量: 通常 5-30 个 (威胁合并/过滤后)                      │   │
│  │  ⚠️ 必填: threat_refs[] 追溯到原始威胁                   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼ (缓解 Phase 7)                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Mitigation (缓解措施)                                   │   │
│  │  ─────────────────                                       │   │
│  │  来源: Phase 7 缓解规划                                   │   │
│  │  ID: M-{Seq}  例: M-001                                  │   │
│  │  性质: 针对验证风险的修复方案                              │   │
│  │  数量: 通常 5-20 个 (可一对多)                            │   │
│  │  包含: risk_refs[] 追溯到验证风险                         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Entity Relationships (实体关系)

```
DFD Element              1:N                 ┌──────────┐
(P01, DS01, DF01...)    ─────────────────────▶│  Threat  │
                                             │ (T-xxx)  │
                                             └────┬─────┘
                                                  │
                                                  │ N:1 (合并)
                                                  ▼
                                        ┌─────────────────┐
Finding ────────────────────────────────▶│ ValidatedRisk   │
(F-xxx)   合并                           │   (VR-xxx)      │
                                        │                 │
                                        │ threat_refs:    │
                                        │ [T-T-P13-001,   │
                                        │  T-T-P13-002,   │
                                        │  T-E-P13-001]   │
                                        └────────┬────────┘
                                                 │
                                                 │ N:1 (覆盖)
                                                 ▼
                                        ┌─────────────────┐
                                        │   Mitigation    │
                                        │    (M-xxx)      │
                                        │                 │
                                        │ risk_refs:      │
                                        │ [VR-001,        │
                                        │  VR-002]        │
                                        └─────────────────┘

关键关系:
• Threat N:1 ValidatedRisk (多威胁合并为一个风险)
• ValidatedRisk N:1 Mitigation (多风险可被同一措施覆盖)
• 所有关系通过 *_refs[] 显式追溯
```

### Unified ID Convention (统一ID规范)

| 实体类型 | ID 格式 | 示例 | 阶段 |
|---------|--------|------|------|
| Finding | F-P{N}-{Seq:03d} | F-P1-001 | P1-P4 |
| Threat | T-{STRIDE}-{Element}-{Seq} | T-T-P13-002 | P5 |
| ValidatedRisk | VR-{Seq:03d} | VR-001 | P6 |
| Mitigation | M-{Seq:03d} | M-001 | P7 |
| POC | POC-{Seq:03d} | POC-001 | P6 |
| AttackPath | AP-{Seq:03d} | AP-001 | P6 |
| AttackChain | AC-{Seq:03d} | AC-001 | P6 |

**❌ 禁止的 ID 格式** (不再使用):
- `RISK-{Seq}` → 改用 `VR-{Seq}`
- `T-E-RCE-001` → 改用 `T-E-P13-001` (保留 ElementID)
- `SD-{Seq}` → 改用 `F-P4-{Seq}`

### Count Conservation Rules (数量守恒规则) ⚠️ CRITICAL

```yaml
# 威胁处理守恒公式
count_conservation:
  p5_output: "threat_inventory.total = T"  # 例: 120
  p6_processing:
    verified: V      # 验证确认的威胁数
    theoretical: Th  # 理论可行的威胁数
    pending: P       # 待验证的威胁数
    excluded: E      # 排除的威胁数 (有理由)

  conservation_formula: "V + Th + P + E = T"

  traceability_rule: |
    FOR each threat T in p5_output:
      T MUST appear in exactly one VR.threat_refs[]
      OR T.status = 'excluded' with documented reason

  report_consistency:
    RISK-INVENTORY.count = "len(VR where status != 'excluded')"
    MAIN-REPORT.risk_count = "RISK-INVENTORY.count"

# 验证检查点
checkpoints:
  cp1_p5_to_p6: "P6.input_count = P5.threat_inventory.summary.total"
  cp2_p6_output: "sum(verified, theoretical, pending, excluded) = input_count"
  cp3_report_gen: "RISK-INVENTORY.count = P6.final_risk_count"
```

### ValidatedRisk Structure (验证风险数据结构)

```yaml
ValidatedRisk:
  # === 标识 ===
  id:
    format: "VR-{Seq:03d}"
    example: "VR-001"

  # === 追溯 (MANDATORY!) ===
  threat_refs:
    type: array[Threat.id]
    description: "此风险来源的所有威胁 ID"
    example: ["T-T-P13-001", "T-T-P13-002", "T-E-P13-001"]
    requirement: "MANDATORY - 必须列出所有源威胁"

  finding_refs:
    type: array[Finding.id]
    description: "此风险来源的 P1-P4 发现"
    example: ["F-P4-003"]
    requirement: "OPTIONAL - 如有关联发现"

  # === 风险评估 ===
  severity:
    cvss_score: float  # 0.0-10.0
    priority: "P0|P1|P2|P3"
    stride_types: ["T", "E"]  # 可包含多个 STRIDE 类型

  # === 验证状态 ===
  validation:
    status: "verified|theoretical|pending|excluded"
    poc_available: boolean
    poc_id: "POC-{Seq}"  # 如有 POC
```

> **详细设计**: 见 `tmp_data/DATA-ARCHITECTURE-DESIGN.md`

### Phase Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              Phase Data Flow Architecture                                            │
├─────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                      │
│  Phase 1          Phase 2          Phase 3          Phase 4          Phase 5                        │
│  ┌─────┐          ┌─────┐          ┌─────┐          ┌─────┐          ┌─────┐                        │
│  │ P1  │─findings1─▶│ P2  │─findings2─▶│ P3  │─findings3─▶│ P4  │─findings4─▶│ P5  │                        │
│  └──┬──┘          └──┬──┘          └──┬──┘          └──┬──┘          └──┬──┘                        │
│     │                ▼                ▼                │                │                           │
│     │           security-        security-             │                │                           │
│     │           design.yaml      design.yaml           │                │                           │
│     │                                                  ▼                ▼                           │
│     │                                          control-set-*.md    CWE → CAPEC                     │
│     │                                          reference-set-*.md                                   │
│     ▼                                                                   │                           │
│  ┌────────────────────────────────────────────────────────────────────────────────────────┐        │
│  │                              Phase 6: Risk Validation                                  │        │
│  │  INPUT: findings_1 + findings_2 + findings_3 + findings_4 + findings_5                │        │
│  │         (ALL issues consolidated and deduplicated)                                     │        │
│  │  KNOWLEDGE: CAPEC → ATT&CK → CVE/KEV + WSTG + MASTG                                   │        │
│  │  OUTPUT: validated_risks                                                              │        │
│  │    ├── risk_summary (counts, categorization)                                          │        │
│  │    ├── risk_details (per-item: location, analysis, root cause, test cases)           │        │
│  │    └── attack_paths (chains, step-by-step with commands/POC)                          │        │
│  └───────────────────────────────────────────────────────────────────────────────────────┘        │
│                                             │                                                       │
│                                             ▼                                                       │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐        │
│  │                              Phase 7: Mitigation Planning                              │        │
│  │  INPUT: validated_risks (complete Phase 6 output)                                     │        │
│  │  KNOWLEDGE: Control Sets + OWASP References + CWE Mitigations + ASVS                  │        │
│  │  OUTPUT: mitigation_plan (per-risk: immediate, short-term, long-term)                 │        │
│  └───────────────────────────────────────────────────────────────────────────────────────┘        │
│                                             │                                                       │
│                                             ▼                                                       │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐        │
│  │                              Phase 8: Report Generation                                │        │
│  │  INPUT: ALL phase outputs (findings_1 → mitigation_plan)                              │        │
│  │  KNOWLEDGE: Compliance Frameworks + ASVS                                              │        │
│  │  CRITICAL: Must include COMPLETE Phase 6 and Phase 7 outputs (no omission)           │        │
│  └───────────────────────────────────────────────────────────────────────────────────────┘        │
│                                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Phase Context Protocol

**Core Principle**: Each phase must explicitly declare Input Context and Output Context for cross-phase data continuity.

| Phase | Context Name | Key Fields |
|-------|--------------|------------|
| P1→P2 | `project_context` | project_type, modules[], integrations[], security_design{} |
| P2→P3 | `dfd_elements` | elements[{id,type,name}], flows[{id,source,target,data}], dfd_diagram |
| P3→P4 | `boundary_context` | boundaries[], interfaces[], data_nodes[], cross_boundary_flows[] |
| P4→P5 | `security_gaps` | gaps[{domain,severity,description}], design_matrix{} |
| P5→P6 | `threat_inventory` | threats[{id,element_id,stride,cwe,priority}] |
| P6→P7 | `validated_risks` | risk_summary{}, risk_details[], attack_paths[] |
| P7→P8 | `mitigation_plan` | mitigations[{risk_id,measures,implementation}], roadmap{} |

### Element ID Naming Convention

**DFD Element ID Format** (Phase 2 generates, subsequent phases must reference):

| Element Type | Prefix | Format | Example |
|--------------|--------|--------|---------|
| External Interactor | EI | EI{NN} | EI01, EI02 |
| Process | P | P{NN} | P01, P02, P03 |
| Data Store | DS | DS{NN} | DS01, DS02 |
| Data Flow | DF | DF{NN} | DF01, DF02 |
| Trust Boundary | TB | TB{NN} | TB01, TB02 |

**Threat ID Format** (Phase 5 generates):
```
T-{STRIDE}-{ElementID}-{Seq}
```
- STRIDE: S/T/R/I/D/E (single letter)
- ElementID: From P2 element ID
- Seq: Three-digit sequence (001-999)
- Example: `T-S-P01-001` (First Spoofing threat for Process 01)

---

## Phase Details

### Phase 1: Project Understanding <ultrathink><critical thinking>

#### 1.1 Core Analysis Goal
> **Goal**: Comprehensively understand project architecture, functional modules, tech stack, and security design decisions.
> This is an **exploratory** task where LLM needs to understand overall project structure through code reading.

#### 1.2 Input Context
**Input**: Project path/codebase

#### 1.3 Knowledge Reference
**Security Principles**: `assets/knowledge/security-principles.yaml`
- Evaluate if project embodies core security principles (DID, LP, ZT)
- Identify obvious security design flaws

#### 1.4 Script Support
```bash
# Get project structure with type detection
python $SKILL_PATH/scripts/list_files.py <path> --categorize --detect-type --pretty
```

#### 1.5 Output Context
**→ P2**: `project_context` {project_type, modules[], integrations[], security_design{}}

**Required Output**:
```markdown
## Project Summary
- Project Type: [Web/API/Microservice/AI-LLM/Hybrid]
- Primary Language: [Language]
- Framework: [Frameworks]

## Functional Description
- Core Functions: [...]
- User Roles: [...]

## Major Modules
| Module | Responsibility | Location |
|--------|---------------|----------|

## Key Security Design
- Authentication: [...]
- Data Storage: [...]
- External Integrations: [...]
```

**Scenario Confirmation** (based on Phase 1 analysis):

| Scenario Type | Trigger Condition | Enable Extension |
|--------------|-------------------|------------------|
| Standard Web/API | No AI/No Cloud-Native | Standard STRIDE flow |
| AI/LLM Application | Model calls/RAG/Prompt processing detected | `--all-llm`, `--ai-component` |
| Cloud-Native App | AWS/Azure/GCP/K8s detected | `--cloud {provider}` |
| Microservices | Multi-service/Docker/K8s | Cross-service threat analysis |
| Hybrid | Multiple features | Combined extensions |

**Checkpoint**: Summarize and reflect before Phase 2.

---

### Phase 2: Call Flow & DFD <ultrathink><critical thinking>

#### 2.1 Core Analysis Goal
> **Goal**: Build Data Flow Diagram (DFD), trace complete data path from entry to storage.
> This is a **constructive** task where LLM needs to understand code call relationships and visualize data flow.

#### 2.2 Input Context
**← P1**: `project_context`

#### 2.3 Knowledge Reference
**Security Principles**: `assets/knowledge/security-principles.yaml`
- Apply Complete Mediation (CM) to identify access checkpoints
- Apply Input Validation (IV) to mark validation points

**Security Design**: `assets/knowledge/security-design.yaml`
- Reference 16 security domains to identify security-relevant DFD elements

#### 2.4 Output Context
**→ P3**: `dfd_elements` {elements[], flows[], dfd_diagram, dfd_issues[]}

**Output Requirements**:
- ASCII DFD diagram (in body)
- Mermaid DFD source (in appendix)
- Element inventory table

**Checkpoint**: Summarize and reflect before Phase 3.

---

### Phase 3: Trust Boundaries <ultrathink><critical thinking>

#### 3.1 Core Analysis Goal
> **Goal**: Based on DFD, identify trust boundaries, key interfaces, and data nodes; evaluate security posture.
> This is an **evaluative** task where LLM needs to identify security boundaries and assess cross-boundary risks.

#### 3.2 Input Context
**← P1/P2**: `project_context`, `dfd_elements`

#### 3.3 Knowledge Reference
**Security Principles**: Apply ZT, SOD, LP principles
**Security Design**: `assets/knowledge/security-design.yaml` - AUTHN, AUTHZ, API domains

#### 3.4 Output Context
**→ P4**: `boundary_context` {boundaries[], interfaces[], data_nodes[], boundary_issues[]}

**Checkpoint**: Summarize and reflect before Phase 4.

---

### Phase 4: Security Design Assessment <ultrathink><critical thinking>

#### 4.1 Core Analysis Goal
> **Goal**: Evaluate project's design maturity across all security domains, identify gaps.
> This is an **evaluative** task requiring LLM to understand code security implementation and compare with best practices.

#### 4.2 Input Context
**← P1/P2/P3**: All cumulative findings

#### 4.3 Knowledge Reference (Progressive Loading)
1. Load `security-design.yaml` - Get all 16 domains with core requirements
2. For each relevant domain, load corresponding `control-set-*.md`
3. When specific implementation details needed, load `reference-set-*.md`

**Query Commands**:
```bash
# Get security domain details
$SKILL_PATH/kb --control authentication
$SKILL_PATH/kb --stride-controls S
```

#### 4.4 Output Context
**→ P5**: `security_gaps` {gaps[], design_matrix{}}

**Required Output**:
```markdown
## Security Design Assessment Matrix
| Domain | Current Implementation | Assessment | Gap | Risk Level | KB Reference |
|--------|----------------------|------------|-----|------------|--------------|
| AUTHN | [...] | Yes/No/Partial | [...] | High/Medium/Low | control-set-01 |
```

**Checkpoint**: Summarize and reflect before Phase 5.

---

### Phase 5: STRIDE Analysis <ultrathink><critical thinking>

#### 5.1 Core Analysis Goal
> **Goal**: Apply STRIDE method to DFD elements, generate complete threat inventory.
> This is an **enumerative** task where LLM systematically identifies potential threats for each element.

#### 5.2 Input Context
**← P2/P4**: `dfd_elements`, `security_gaps`

#### 5.3 Knowledge Reference
**Threat Pattern Set**: CWE → CAPEC mapping

**Query Commands**:
```bash
$SKILL_PATH/kb --stride spoofing           # STRIDE category details
$SKILL_PATH/kb --full-chain CWE-XXX        # Complete chain: STRIDE→CWE→CAPEC→ATT&CK
$SKILL_PATH/kb --all-llm                    # LLM threats (AI components)
```

#### 5.4 STRIDE per Element Matrix

| Element Type | Applicable STRIDE |
|--------------|-------------------|
| Process | S, T, R, I, D, E (all 6) |
| Data Store | T, R, I, D |
| Data Flow | T, I, D |
| External Entity (as source) | S, R |

#### 5.5 Output Context
**→ P6**: `threat_inventory` {threats[{id, element_id, stride, cwe, priority}]}

**Checkpoint**: Summarize and reflect before Phase 6.

---

### Phase 6: Risk Validation <ultrathink><critical thinking>

> **📄 Detailed Workflow**: See `@VALIDATION.md` for complete Phase 6 workflow, consolidation process, and POC templates.

#### 6.1 Core Analysis Goal
> **Goal**: Consolidate ALL findings from P1-P5, perform deep validation, design attack paths and POC.
> This is a **verification** task where LLM thinks from attacker's perspective.

#### 6.2 Input Context
**← ALL P1-P5**: findings_1 + findings_2 + findings_3 + findings_4 + findings_5

**CRITICAL**: Phase 6 must consolidate ALL previous findings, not just Phase 5 threats.

#### 6.3 Knowledge Reference
**Threat Pattern Set**: CAPEC → ATT&CK → CVE/KEV
**Verification Set**: WSTG + MASTG (test generation)

**Query Commands**:
```bash
# Attack path analysis
$SKILL_PATH/kb --capec CAPEC-XXX --attack-chain
$SKILL_PATH/kb --attack-technique TXXX
$SKILL_PATH/kb --check-kev CVE-XXXX

# Verification tests
$SKILL_PATH/kb --stride-tests S              # STRIDE category tests
$SKILL_PATH/kb --cwe-tests CWE-89            # CWE-specific tests
$SKILL_PATH/kb --wstg-category ATHN          # WSTG tests by category
```

#### 6.4 Output Structure (5 Parts)

> **Schema Reference**: `assets/schemas/risk-detail.schema.md` defines complete risk detail format.
> **Template Reference**: `assets/templates/RISK-ASSESSMENT-REPORT.template.md` Section 5-6 for output format.

**Priority Mapping** (from schema):

| CVSS 评分 | 严重程度 | 优先级 | 行动要求 |
|-----------|---------|--------|----------|
| 9.0 - 10.0 | Critical | P0 | 立即修复 |
| 7.0 - 8.9 | High | P1 | 紧急处理 (24h) |
| 4.0 - 6.9 | Medium | P2 | 高优先级 (7d) |
| 0.1 - 3.9 | Low | P3 | 计划中 (30d) |

**POC Verification Status Types**:

| 状态标识 | 含义 | 判定标准 |
|---------|------|---------|
| ✅ **已验证** | POC 执行成功 | 成功复现攻击行为并获得预期结果 |
| ⚠️ **需验证** | 理论可行但需手动验证 | 需要特定环境或权限才能验证 |
| 📋 **理论可行** | 基于代码分析推导 | 代码路径存在但未实际测试 |
| ❌ **已排除** | 验证后确认不可利用 | 存在缓解措施或条件不满足 |

```yaml
validated_risks:
  # Part 1: Risk Summary (验证覆盖统计)
  risk_summary:
    total_identified: N
    total_verified: N                           # ✅ 已验证
    total_pending: N                            # ⚠️ 需验证
    total_theoretical: N                        # 📋 理论可行
    total_excluded: N                           # ❌ 已排除
    verification_rate: "N%"
    risk_by_severity: {critical: N, high: N, medium: N, low: N}
    risk_by_stride: {S: N, T: N, R: N, I: N, D: N, E: N}

  # Part 2: POC Details (每个 Critical/High 威胁一个完整块)
  poc_details:
    - poc_id: "POC-001"                         # Format: POC-{SEQ:03d}
      threat_ref: "T-S-P01-001"                 # 关联威胁ID
      stride_type: "S"                          # STRIDE类型
      verification_status: "verified"           # verified|pending|theoretical|excluded
      exploitation_difficulty: "medium"         # low|medium|high
      prerequisites:                            # 前置条件
        - "有效的用户会话"
        - "知道目标用户ID"
      vulnerability_location:
        file_path: "src/api/auth.py"
        function_name: "verify_token"
        line_number: 45
      vulnerable_code: |                        # 漏洞代码片段
        def verify_token(token):
            # 缺少签名验证
            return jwt.decode(token, options={"verify_signature": False})
      exploitation_steps:                       # 利用步骤
        - "构造恶意JWT Token"
        - "发送请求到认证端点"
        - "绕过身份验证"
      poc_code: |                               # POC代码 (完整可执行)
        import jwt
        # 构造恶意token
        malicious_token = jwt.encode({"user_id": "admin"}, "any_key", algorithm="HS256")
        # 发送请求...
      expected_result: |                        # 预期结果
        {"status": "authenticated", "user": "admin"}
      verification_log: "..."                   # 验证日志/截图
      risk_assessment:
        complexity: "medium"
        attack_vector: "network"
        impact_scope: "user_data"
        data_sensitivity: "high"

  # Part 3: Risk Details (per item) - See assets/schemas/risk-detail.schema.md
  risk_details:
    - risk_id: "VR-001"                         # Format: VR-{SEQ:03d}
      original_refs: ["T-S-P01-001", "SD-001"]  # From multiple phases
      priority: "P1"                             # P0/P1/P2/P3
      location: {files: [], elements: [], trust_boundary: ""}
      detailed_analysis: {...}
      root_cause: {...}
      related_cwe: "CWE-XXX"                     # Required field
      related_poc: "POC-001"                     # Link to POC detail
      validation:
        test_cases: []
        poc_available: true
        cvss_score: 8.8
        verification_status: "verified"

  # Part 4: Attack Path Feasibility Matrix (可行性评分)
  attack_path_matrix:
    - path_id: "AP-001"
      path_name: "认证绕过→数据库访问"
      entry_point: "API Gateway"
      key_nodes: ["Auth Service"]
      final_target: "数据库"
      feasibility_score: 8.5                    # 0.0-10.0
      detection_difficulty: "low"               # low|medium|high
      priority_fix: true

  # Part 5: Attack Chains (完整攻击链分析)
  attack_chains:
    - chain_id: "AC-001"
      chain_name: "权限提升攻击链"
      entry_point: "公共API端点"
      target: "管理员权限"
      impact_scope: "完全系统控制"
      difficulty: "medium"
      related_threats: ["T-E-P01-001", "T-S-P02-001"]
      steps:
        - step: 1
          title: "初始访问"
          source: "攻击者"
          target: "API网关"
          action: "发送恶意请求"
          code_location: "api/routes.py:120"
          data_change: "获得会话token"
        - step: 2
          title: "权限提升"
          source: "API网关"
          target: "认证服务"
          action: "利用JWT漏洞"
          code_location: "auth/jwt.py:45"
          data_change: "获得管理员角色"
      # ASCII 攻击链图 (必须在报告中展示)
      attack_flow_diagram: |
        ┌─────────────────────────────────────────────────────────────────┐
        │                     攻击链: 权限提升攻击                         │
        ├─────────────────────────────────────────────────────────────────┤
        │  Step 1: 初始访问                                               │
        │  ┌─────────────────────────────────────────────────────────┐   │
        │  │  攻击者 ──→ API网关                                       │   │
        │  │  动作: 发送恶意请求                                        │   │
        │  │  代码位置: api/routes.py:120                              │   │
        │  └─────────────────────────────────────────────────────────┘   │
        │                              │                                   │
        │                              ▼                                   │
        │  Step 2: 权限提升                                               │
        │  ┌─────────────────────────────────────────────────────────┐   │
        │  │  API网关 ──→ 认证服务                                     │   │
        │  │  动作: 利用JWT漏洞获得管理员角色                           │   │
        │  │  代码位置: auth/jwt.py:45                                 │   │
        │  └─────────────────────────────────────────────────────────┘   │
        │                              │                                   │
        │                              ▼                                   │
        │  结果: 获得管理员权限，完全系统控制                              │
        └─────────────────────────────────────────────────────────────────┘
      prerequisites:
        - "网络访问权限"
        - "基础用户账户"
      exploitation_commands: |
        # Step 1: 获取初始token
        curl -X POST https://target/api/login -d '{"user":"test","pass":"test"}'
        # Step 2: 构造提权token
        python3 jwt_exploit.py --token $TOKEN --role admin
      ioc_indicators:
        - "异常的JWT token结构"
        - "短时间内角色变更"
      defense_recommendations:
        - cutpoint: "Step 1"
          recommendation: "实施请求速率限制和异常检测"
        - cutpoint: "Step 2"
          recommendation: "启用JWT签名验证，使用强密钥"
```

#### 6.5 Output Quality Requirements

**CRITICAL**: Phase 6 output MUST include:
1. **POC Details**: Every Critical/High threat must have a complete POC block with executable code
2. **Attack Chains**: At least one detailed attack chain diagram per high-risk attack path
3. **Feasibility Matrix**: All attack paths must have feasibility scores (0.0-10.0)
4. **ASCII Diagrams**: Attack chains must include ASCII box diagrams in `attack_flow_diagram` field

**Checkpoint**: Summarize and reflect before Phase 7.

---

### Phase 7: Mitigation Planning <ultrathink><critical thinking>

> **📄 Detailed Workflow**: See `@REPORT.md` for complete Phase 7-8 workflow with content aggregation instructions.

#### 7.1 Core Analysis Goal
> **Goal**: Design specific mitigation measures and implementation plans for each validated risk.
> This is a **prescriptive** task requiring LLM to design feasible security controls for the tech stack.

#### 7.2 Input Context
**← P6**: `validated_risks` (complete Phase 6 output)

#### 7.3 Knowledge Reference
**Security Control Set**: Control Sets + OWASP References
**Threat Pattern Set**: CWE Mitigations
**Verification Set**: ASVS (requirement verification)

**Query Commands**:
```bash
$SKILL_PATH/kb --cwe CWE-XXX --mitigations    # CWE mitigations
$SKILL_PATH/kb --control authentication        # Security controls
$SKILL_PATH/kb --asvs-level L2                 # ASVS requirements
$SKILL_PATH/kb --asvs-chapter V4               # ASVS by chapter
```

#### 7.4 Output Context
**→ P8**: `mitigation_plan` {mitigations[], roadmap{}}

**Required Output for Each Risk**:
```markdown
### Mitigation Measures
| Risk ID | CWE | Recommended Measure | Implementation | Priority | Effort |
|---------|-----|---------------------|----------------|----------|--------|
| VR-XXX | CWE-XXX | [Measure] | [Code/Config] | Critical/High/Medium/Low | [Est.] |
```

**Checkpoint**: Summarize and reflect before Phase 8.

---

### Phase 8: Comprehensive Report <ultrathink><critical thinking>

> **📄 Detailed Workflow**: See `@REPORT.md` for complete Phase 8 workflow with **mandatory content aggregation rules**.
> **⚠️ CRITICAL**: Phase 8 MUST read all phase files and copy content completely — do NOT summarize from memory!

#### 8.1 Core Analysis Goal
> **Goal**: Synthesize all phase outputs into complete threat model report.
> This is a **comprehensive** task where LLM integrates all 7 phases of analysis.

#### 8.2 Input Context
**← P1-P7**: ALL preceding phase outputs

#### 8.3 Knowledge Reference
**Compliance Frameworks** + **ASVS** (compliance verification)

```bash
$SKILL_PATH/kb --compliance nist-csf
$SKILL_PATH/kb --asvs-level L2 --chapter V1
```

#### 8.4 ⚠️ MANDATORY: Output Directory Setup

**在生成任何报告之前，必须执行以下步骤**:

1. **确定 PROJECT 名称**: 从项目名提取，转换为大写
   - 示例: `open-webui` → `OPEN-WEBUI`
   - 格式: `^[A-Z][A-Z0-9-]{0,29}$`

2. **创建输出目录**:
   ```bash
   mkdir -p {PROJECT_ROOT}/Risk_Assessment_Report/
   ```

3. **所有报告必须输出到此目录**:
   - 主报告: `Risk_Assessment_Report/{PROJECT}-RISK-ASSESSMENT-REPORT.md`
   - 风险清单: `Risk_Assessment_Report/{PROJECT}-RISK-INVENTORY.md`
   - 缓解措施: `Risk_Assessment_Report/{PROJECT}-MITIGATION-MEASURES.md`

⚠️ **禁止**: 直接在项目根目录创建报告文件！

#### 8.5 Report Structure (9 Sections + Appendix)
**CRITICAL**: Sections 5, 6, and 8 must include COMPLETE Phase 6 and Phase 7 outputs without omission.

> **Template Reference**: `assets/templates/RISK-ASSESSMENT-REPORT.template.md`

```markdown
# {PROJECT}-RISK-ASSESSMENT-REPORT.md

## 1. 执行摘要 (Executive Summary)
- 威胁统计、STRIDE分布、关键发现、立即行动建议

## 2. 系统架构概览 (System Architecture)
- 组件拓扑ASCII图、数据流图DFD、信任边界、技术栈
- (from findings_1, findings_2, findings_3)

## 3. 安全功能设计评估 (Security Design Assessment)
- 9安全域评估矩阵、关键安全发现详情
- (from findings_4)

## 4. STRIDE 威胁分析 (STRIDE Threat Analysis)
- 威胁汇总表、按STRIDE分类表、威胁详细分析
- (from findings_5)

## 5. 风险验证与POC设计 (Risk Validation & POC) ← CRITICAL
- POC验证方法论、验证覆盖统计、POC验证详情、POC汇总表
- 每个Critical/High威胁必须有完整POC代码块
- (from validated_risks.poc_details)

## 6. 攻击路径分析 (Attack Path Analysis) ← CRITICAL
- 攻击路径可行性矩阵、攻击链详细分析、攻击面热力图、优先级排序
- 每条高危攻击路径必须有ASCII攻击链图
- (from validated_risks.attack_chains, validated_risks.attack_path_matrix)

## 7. 威胁优先级矩阵 (Threat Priority Matrix)
- 风险评估矩阵、威胁分布矩阵、攻击面热力图

## 8. 缓解措施建议 (Mitigation Recommendations) ← CRITICAL
- P0/P1/P2分级措施、实施路线图、防御纵深架构
- (from mitigation_plan)

## 9. 合规性映射 (Compliance Mapping)
- OWASP Top 10映射、OWASP LLM Top 10映射(如适用)

## 附录 (Appendices)
- A: DFD元素完整清单
- B: Mermaid DFD源码
- C: 威胁完整清单
- D: 知识库查询记录
- E: 参考资料
```

#### 8.6 Output Files

**输出目录**: `{PROJECT_ROOT}/Risk_Assessment_Report/`

**必需报告** (始终生成):
| 序号 | 报告文件 | 说明 |
|------|---------|------|
| 1 | `{PROJECT}-RISK-ASSESSMENT-REPORT.md` | 风险评估报告 (主报告) |
| 2 | `{PROJECT}-RISK-INVENTORY.md` | 风险清单 |
| 3 | `{PROJECT}-MITIGATION-MEASURES.md` | 缓解措施 |
| 4 | `{PROJECT}-PENETRATION-TEST-PLAN.md` | 渗透测试方案 |

#### 8.7 ⚠️ MANDATORY: Phase Output Publication

**在生成所有报告后，必须执行阶段过程文档发布**:

将 `.phase_working/` 中的阶段产物复制到 `Risk_Assessment_Report/` 目录，**保留英文文件名**:

```yaml
phase_output_publication:
  source_dir: ".phase_working/"
  target_dir: "Risk_Assessment_Report/"
  files:  # 直接复制，保留原文件名
    - P1-PROJECT-UNDERSTANDING.md    # Phase 1 项目理解
    - P2-DFD-ANALYSIS.md             # Phase 2 DFD分析
    - P3-TRUST-BOUNDARY.md           # Phase 3 信任边界
    - P4-SECURITY-DESIGN-REVIEW.md   # Phase 4 安全设计评估
    - P5-STRIDE-THREATS.md           # Phase 5 STRIDE威胁分析
    - P6-RISK-VALIDATION.md          # Phase 6 风险验证
```

**执行命令** (示例):
```bash
# 复制阶段过程文档到报告目录 (保留英文名)
cp .phase_working/P1-PROJECT-UNDERSTANDING.md Risk_Assessment_Report/
cp .phase_working/P2-DFD-ANALYSIS.md Risk_Assessment_Report/
cp .phase_working/P3-TRUST-BOUNDARY.md Risk_Assessment_Report/
cp .phase_working/P4-SECURITY-DESIGN-REVIEW.md Risk_Assessment_Report/
cp .phase_working/P5-STRIDE-THREATS.md Risk_Assessment_Report/
cp .phase_working/P6-RISK-VALIDATION.md Risk_Assessment_Report/
```

**价值说明**:
- 阶段过程文档记录完整分析过程
- 支持审计追溯和质量验证
- 便于团队理解威胁建模推导逻辑
- 保留英文名确保命名规范一致性

---

## Scripts Reference

| Script | Purpose | Key Commands |
|--------|---------|--------------|
| `list_files.py` | Phase 1: File listing | `--categorize`, `--detect-type` |
| `stride_matrix.py` | Phase 5: STRIDE matrix | `--element`, `--generate-id` |
| `unified_kb_query.py` | **Phase 4-8: KB queries** | See below |

### unified_kb_query.py - Complete Parameter Reference

#### STRIDE Queries
```bash
--stride {spoofing|tampering|repudiation|information_disclosure|denial_of_service|elevation_of_privilege}
--all-stride                    # All STRIDE categories overview
--element {process|data_store|data_flow|external_interactor}
```

#### CWE Queries
```bash
--cwe CWE-XXX                   # Query specific CWE
--cwe CWE-XXX --mitigations     # Include detailed mitigations
--full-chain CWE-XXX            # Complete chain: STRIDE→CWE→CAPEC→ATT&CK
```

#### CAPEC Attack Patterns
```bash
--capec CAPEC-XXX               # Query specific CAPEC
--capec CAPEC-XXX --attack-chain  # Include ATT&CK technique mapping
```

#### ATT&CK Techniques
```bash
--attack-technique TXXX         # Query ATT&CK technique
--attack-mitigation MXXX        # Query ATT&CK mitigation
--attack-search "keyword"       # Search ATT&CK techniques
```

#### CVE Queries
```bash
--cve CVE-XXXX-XXXXX            # Direct CVE query
--cve-for-cwe CWE-XXX           # CVEs by CWE
--cve-severity {CRITICAL|HIGH|MEDIUM|LOW}
--check-kev CVE-XXXX            # Check Known Exploited Vulnerability
```

#### Verification Set Queries (NEW)
```bash
--stride-tests {S|T|R|I|D|E}    # Get verification tests for STRIDE category
--cwe-tests CWE-XXX             # Get verification tests for CWE
--asvs-level {L1|L2|L3}         # Get ASVS requirements by level
--asvs-chapter {V1|V2|...}      # Get ASVS requirements by chapter
--wstg-category {ATHN|AUTHZ|...}  # Get WSTG tests by category
```

#### Cloud & LLM Extensions
```bash
--cloud {aws|azure|gcp|alibaba|tencent}
--category {compute|storage|database|networking|identity|serverless}
--llm LLM01                     # Query OWASP LLM Top 10
--all-llm                       # All OWASP LLM Top 10 threats
--ai-component {llm_inference_service|rag_retrieval|...}
```

#### Semantic Search
```bash
--semantic-search "query"       # Natural language search
--search-type {cwe|capec|all}
```

---

## Knowledge Base Layers

| Layer | Source | Content | Use Case |
|-------|--------|---------|----------|
| **L1: Curated** | YAML + Markdown | Security domains, controls, references | Phase 2-4 |
| **L2: Indexed** | SQLite (18MB) | 974 CWEs, 615 CAPECs, 835 ATT&CK | Phase 5-7 |
| **L3: Extension** | SQLite (304MB) | 323K+ CVEs | Phase 6 CVE lookup |
| **L4: Live** | NVD/KEV API | Real-time CVE/KEV | Exploit context |
| **L5: Verification** | SQLite | WSTG, MASTG, ASVS | Phase 6-8 |

---

## Parallel Sub-Agent Pattern <ultrathink><critical thinking>

For Phases 5/6/7 with multiple risks:

```
Main Agent                    Sub-Agents (Parallel)
    │                         ┌─────────────────┐
    │──► Risk 1 ──────────────► Agent 1 ──► KB Query ──► Result 1
    │                         └─────────────────┘
    │                         ┌─────────────────┐
    │──► Risk 2 ──────────────► Agent 2 ──► KB Query ──► Result 2
    │                         └─────────────────┘
    │                         ┌─────────────────┐
    │──► Risk N ──────────────► Agent N ──► KB Query ──► Result N
    │                         └─────────────────┘
    │
    ◄───────────────── Aggregate Results ──────────────────
```

---

## Large Project Handling

| Scale | File Count | Module Count | Strategy |
|-------|------------|--------------|----------|
| Small | <50 | <5 | Standard 8-phase analysis |
| Medium | 50-200 | 5-15 | Module-priority (key modules deep) |
| Large | 200-500 | 15-30 | Subsystem split + merge |
| Very Large | >500 | >30 | Layered analysis + parallel sub-agents |

**Subsystem Threat ID**: `T-{STRIDE}-{SubsysID}-{ElementID}-{Seq}`

---

## Common Pitfalls

| Pitfall | Solution |
|---------|----------|
| Skipping phases | Execute all 8 phases in order |
| Not using KB queries | Use `unified_kb_query.py` for every risk |
| Generic mitigations | Query CWE-specific mitigations from KB |
| Missing attack paths | Use CAPEC + ATT&CK for verification |
| No reflection | Summarize and reflect after each phase |
| Parallel phase execution | Phases are strictly serial |
| Incomplete Phase 6 consolidation | Must include ALL P1-P5 findings |
| Phase 8 omissions | Must include COMPLETE P6 and P7 outputs |

---

## Reference Files

**Workflow & Phase Details** (load progressively):
- `@WORKFLOW.md` - Phase 1-5 detailed workflow
- `@VALIDATION.md` - Phase 6 (Risk Validation) complete workflow, consolidation process, POC templates
- `@REPORT.md` - Phase 7-8 (Mitigation & Report) with **mandatory content aggregation rules**
- `EXAMPLES.md` - Real-world threat modeling examples

**Schemas** (format specifications):
- `assets/schemas/risk-detail.schema.md` - Risk detail format, priority mapping (P0-P3), required fields
- `assets/schemas/phase-risk-summary.schema.md` - Phase output summary format (if exists)

**Knowledge Base** (query via scripts—do NOT load directly):
- `assets/knowledge/security_kb.sqlite` - Core database
- `assets/knowledge/security_kb_extension.sqlite` - CVE extension
- `assets/knowledge/*.yaml` - Curated mappings
- `assets/knowledge/security-controls/*.md` - Control sets
- `assets/knowledge/security-controls/references/*.md` - OWASP references
