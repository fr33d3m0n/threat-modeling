<!-- Threat Modeling Skill | Version 3.0.0 (20260202a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Phase 5: STRIDE Threat Analysis

**Type**: Enumerative
**Executor**: LLM
**Knowledge**: CWE → CAPEC (Threat Pattern Set)

---

## ⚠️ MANDATORY: 4-Phase Gating Protocol (BLOCKING)

> **CRITICAL**: 必须按顺序完成以下四个阶段，并**输出每个阶段的结果**。跳过任何阶段将导致分析质量下降！

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🧠 THINKING - Phase 5 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Purpose**: 系统化应用STRIDE方法到所有DFD元素，不遗漏任何元素。

**⚠️ 你必须输出以下格式的 THINKING 结果：**

```
🧠 THINKING - P5 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 CORE PROBLEM
为每个DFD元素应用STRIDE分析，生成完整威胁清单

📊 UPSTREAM DATA (从 P2/P3/P4 YAML 读取)
| 指标 | 值 | 来源 |
|------|-----|------|
| P2进程数 | {实际值} | P2_dfd_elements.yaml → dfd_elements.processes 长度 |
| P2数据存储数 | {实际值} | P2_dfd_elements.yaml → dfd_elements.data_stores 长度 |
| P2数据流数 | {实际值} | P2_dfd_elements.yaml → dfd_elements.data_flows 长度 |
| P2外部交互者数 | {实际值} | P2_dfd_elements.yaml → dfd_elements.external_interactors 长度 |
| P3边界数 | {实际值} | P3_boundary_context.yaml → boundary_context.boundaries 长度 |
| P4 Gap数 | {实际值} | P4_security_gaps.yaml → security_gaps.summary.total_gaps |

❓ UNKNOWNS
- 每个元素的具体威胁场景
- CWE/CAPEC精确映射
- 跨边界威胁的严重性放大

⚠️ RISKS
- 元素覆盖率 < 100%
- STRIDE完整性 < 80% (某些元素缺少应有的STRIDE类别)
- KB富化覆盖率过低
- P0/P1威胁缺少CWE映射

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⛔ STOP CHECK
- P2 YAML 已读取? [YES/NO]
- P3 YAML 已读取? [YES/NO]
- P4 YAML 已读取? [YES/NO]
- 上游数据完整 (DFD元素数/边界数/Gap数均有值)? [YES/NO]
- 可以继续PLANNING? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ **STOP条件**: 如果任何 STOP CHECK = NO → 先读取上游数据再继续

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 📋 PLANNING - Sub-task Decomposition
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Step 1: 读取上游数据** (BLOCKING - 必须执行)
```bash
# 读取P2/P3/P4 YAML数据
python scripts/phase_data.py --query --phase 2 --type dfd --root .
python scripts/phase_data.py --query --phase 3 --summary --root .
python scripts/phase_data.py --query --phase 4 --type gaps --root .

# 或直接读取
cat .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
cat .phase_working/{SESSION_ID}/data/P3_boundary_context.yaml
cat .phase_working/{SESSION_ID}/data/P4_security_gaps.yaml
```
⛔ 如果任何上游YAML不存在或无效 → STOP并返回完成上游Phase

**Step 2: 输出子任务表格** (MANDATORY)

**⚠️ 你必须输出以下格式的 PLANNING 结果：**

```
📋 PLANNING - P5 Sub-tasks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| # | 子任务 | 预期输出 |
|---|--------|----------|
| T1 | 读取P2/P3/P4数据，提取DFD元素和Gap清单 | 数据结构 |
| T2 | 对所有Process应用STRIDE (S,T,R,I,D,E) | 进程威胁 |
| T3 | 对所有DataStore应用STRIDE (T,R,I,D) | 存储威胁 |
| T4 | 对所有DataFlow应用STRIDE (T,I,D) | 流威胁 |
| T5 | 对所有ExternalInteractor应用STRIDE (S,R) | 交互威胁 |
| T6 | KB富化 - CWE/CAPEC/ATT&CK映射 | 威胁富化 |
| T7 | 写入最终输出 | P5_threat_inventory.yaml + MD |

⛔ PLANNING CHECK
- 子任务已分解? [YES/NO]
- 准备创建 TaskCreate? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Step 3: TaskCreate for ALL sub-tasks** (MANDATORY)

⚠️ 在开始任何实施前，必须执行 `TaskCreate` 创建所有子任务！

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### ⚡ EXECUTION LOOP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For each sub-task:
1. `TaskUpdate(status: "in_progress")`
2. 实施子任务
3. 验证: 输出是否符合预期？
4. If 验证通过: `TaskUpdate(status: "completed")` → 下一个
5. If 验证失败: 诊断 → 修复 → 重试 (max 3x) → 如仍失败: CHECKPOINT请求用户决策

**输出顺序** (CRITICAL):
1. **先写YAML**: `.phase_working/{SESSION_ID}/data/P5_threat_inventory.yaml`
2. **后写MD**: `.phase_working/{SESSION_ID}/reports/P5-STRIDE-THREATS.md`

**关键KB查询**:
```bash
$SKILL_PATH/kb --stride spoofing           # STRIDE类别详情
$SKILL_PATH/kb --full-chain CWE-89         # 完整链: STRIDE→CWE→CAPEC→ATT&CK
$SKILL_PATH/kb --cwe CWE-287               # 特定CWE详情
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🔍 REFLECTION - Completion Verification
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**⚠️ 完成 EXECUTION 后，你必须输出以下格式的 REFLECTION 结果：**

```
🔍 REFLECTION - P5 Completion Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 检查项 | 状态 |
|--------|------|
| P2/P3/P4 YAML数据已读取并理解? | [✅/❌] |
| P5_threat_inventory.yaml 存在且有效? | [✅/❌] |
| element_coverage_verification 存在? | [✅/❌] |
| processes.coverage_percentage == 100%? | [✅/❌] |
| data_stores.coverage_percentage == 100%? | [✅/❌] |
| data_flows.coverage_percentage == 100%? | [✅/❌] |
| external_interactors.coverage_percentage == 100%? | [✅/❌] |
| stride_completeness >= 0.80? | [✅/❌] |
| kb_enrichment_log 存在? | [✅/❌] |
| P0/P1威胁全部有CWE映射? | [✅/❌] |
| summary.total 与threats[]长度一致? | [✅/❌] |
| Hook验证通过 (exit 0)? | [✅/❌] |

⛔ COMPLETION GATE
- 所有检查通过? [YES/NO]
- 可以进入P6? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ 任何检查失败 → 修复并重新验证，直到全部通过

---

## ⚠️ MANDATORY OUTPUT RULES

> **CRITICAL**: Phase 5 requires TWO outputs - a YAML data file AND a Markdown report.

### Dual Output Requirement

```
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 5 MUST PRODUCE TWO FILES:                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. DATA FILE (PRIMARY - Write First!)                              │
│     Path: .phase_working/{SESSION_ID}/data/P5_threat_inventory.yaml │
│     Purpose: Structured threat data for P6 to read                  │
│     Format: Valid YAML with schema_version: "3.0.0 (20260201a)"                   │
│                                                                      │
│  2. REPORT FILE (SECONDARY - Write After Data!)                     │
│     Path: .phase_working/{SESSION_ID}/reports/P5-STRIDE-THREATS.md  │
│     Purpose: Human-readable STRIDE analysis report                  │
│     Format: Markdown with threat tables and matrices                │
│                                                                      │
│  INPUT REQUIREMENT:                                                  │
│     Read: .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml     │
│     Read: .phase_working/{SESSION_ID}/data/P4_security_gaps.yaml    │
│     ❌ DO NOT read previous .md reports for data extraction         │
│     ✅ REQUIRED: Parse YAML files for dfd_elements, security_gaps   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Required Data Sections in YAML

| Section | Validation |
|---------|------------|
| `threat_inventory.threats[]` | BLOCKING - all threats with T-xxx-xxx IDs |
| `threat_inventory.summary` | BLOCKING - by_stride, by_priority counts |

### Validation Gate

Phase 5 CANNOT complete until:
1. `.phase_working/{SESSION_ID}/data/P5_threat_inventory.yaml` exists and is valid YAML
2. Every DFD element has associated threats (per STRIDE matrix)
3. Summary totals match threat list count
4. `.phase_working/{SESSION_ID}/reports/P5-STRIDE-THREATS.md` exists
5. Element coverage verification shows 100% coverage

### Element Coverage Verification (CRITICAL)

**P5 MUST verify complete STRIDE coverage of ALL P2 DFD elements**:

```yaml
# In P5_threat_inventory.yaml - REQUIRED section
element_coverage_verification:
  # P2 Input Reference
  p2_input_ref: "P2_dfd_elements.yaml"

  # Process Coverage (STRIDE: S,T,R,I,D,E)
  processes:
    total_from_p2: 12              # Count from P2.dfd_elements.processes
    elements_with_threats: 12     # Processes that have at least one threat
    coverage_percentage: 100      # MUST be 100%
    uncovered_elements: []        # MUST be empty
    stride_coverage:              # Each process should have S,T,R,I,D,E
      P-001: {S: 2, T: 3, R: 1, I: 2, D: 1, E: 2}  # Count per category
      P-002: {S: 1, T: 2, R: 1, I: 1, D: 1, E: 1}
      # ... all processes

  # Data Store Coverage (STRIDE: T,R,I,D)
  data_stores:
    total_from_p2: 5
    elements_with_threats: 5
    coverage_percentage: 100
    uncovered_elements: []
    stride_coverage:              # Each store should have T,R,I,D
      DS-001: {T: 2, R: 1, I: 3, D: 1}
      # ... all data stores

  # Data Flow Coverage (STRIDE: T,I,D)
  data_flows:
    total_from_p2: 25
    elements_with_threats: 25
    coverage_percentage: 100
    uncovered_elements: []
    stride_coverage:              # Each flow should have T,I,D
      DF-001: {T: 1, I: 2, D: 1}
      # ... all data flows

  # External Interactor Coverage (STRIDE: S,R)
  external_interactors:
    total_from_p2: 3
    elements_with_threats: 3
    coverage_percentage: 100
    uncovered_elements: []
    stride_coverage:              # Each interactor should have S,R
      EI-001: {S: 2, R: 1}
      # ... all external interactors

  # Overall Coverage Summary
  overall:
    total_dfd_elements: 45        # Sum of all element types
    elements_covered: 45          # Elements with at least one threat
    coverage_percentage: 100      # MUST be 100%
    stride_completeness: 0.95     # % of applicable STRIDE categories covered

  # ============================================================
  # GAP-6 FIX: STRIDE Completeness Per-Element Verification
  # Ensures EVERY element has threats for ALL applicable STRIDE categories
  # ============================================================
  stride_completeness_detail:
    # Expected STRIDE categories per element type (from STRIDE per Element matrix)
    expected_categories:
      Process: [S, T, R, I, D, E]       # 6 categories
      DataStore: [T, R, I, D]           # 4 categories
      DataFlow: [T, I, D]               # 3 categories
      ExternalInteractor: [S, R]        # 2 categories

    # Per-element STRIDE completeness validation
    element_stride_completeness:
      # Process completeness (must have all 6: S,T,R,I,D,E)
      processes:
        P-001:
          expected: [S, T, R, I, D, E]
          actual: [S, T, R, I, D, E]
          complete: true
          missing: []
        P-002:
          expected: [S, T, R, I, D, E]
          actual: [S, T, R, I, D]      # Missing E
          complete: false
          missing: [E]
          missing_reason: "Elevation of Privilege considered N/A due to sandboxed process"
        # ... all processes

      # Data store completeness (must have all 4: T,R,I,D)
      data_stores:
        DS-001:
          expected: [T, R, I, D]
          actual: [T, R, I, D]
          complete: true
          missing: []
        # ... all data stores

      # Data flow completeness (must have all 3: T,I,D)
      data_flows:
        DF-001:
          expected: [T, I, D]
          actual: [T, I, D]
          complete: true
          missing: []
        # ... all data flows

      # External interactor completeness (must have all 2: S,R)
      external_interactors:
        EI-001:
          expected: [S, R]
          actual: [S, R]
          complete: true
          missing: []
        # ... all external interactors

    # Summary statistics
    completeness_summary:
      processes:
        total: 12
        fully_complete: 11          # All 6 STRIDE categories present
        partially_complete: 1       # Some categories missing with reason
        stride_completeness: 0.97   # (11×6 + 5) / (12×6) = 0.97
      data_stores:
        total: 5
        fully_complete: 5
        partially_complete: 0
        stride_completeness: 1.0
      data_flows:
        total: 25
        fully_complete: 24
        partially_complete: 1
        stride_completeness: 0.99
      external_interactors:
        total: 3
        fully_complete: 3
        partially_complete: 0
        stride_completeness: 1.0

    # Overall STRIDE completeness (weighted)
    overall_stride_completeness:
      total_expected_categories: 182    # (12×6) + (5×4) + (25×3) + (3×2)
      total_actual_categories: 180      # Actual count
      completeness_percentage: 98.9     # 180/182
      missing_categories_count: 2
      missing_categories_documented: true  # All missing have reasons

    # Missing category documentation (REQUIRED for any missing STRIDE)
    missing_stride_documentation:
      - element_id: P-002
        element_type: Process
        missing_category: E
        reason: "Process runs in isolated sandbox with no privilege escalation path"
        verified_by: "Code review confirmed no setuid, no sudo, no capability changes"
      - element_id: DF-015
        element_type: DataFlow
        missing_category: D
        reason: "Internal async queue with rate limiting - DoS not applicable"
        verified_by: "Rate limiter configured at 1000 req/s with backpressure"
```

**Validation Rules** (GAP-6 Enhanced):
- **Element Coverage**: Every element from P2 MUST have at least one threat (coverage_percentage == 100%)
- **STRIDE Completeness**: Every element SHOULD have threats for ALL applicable STRIDE categories
- **Missing Category Documentation**: Any missing STRIDE category MUST have documented reason and verification

**BLOCKING**:
- `coverage_percentage < 100%` for any element type
- `missing_categories_documented == false` (missing STRIDE without explanation)

**WARNING** (threshold = 0.80, recommended = 0.95):
- `stride_completeness < 0.80` - Below minimum acceptable STRIDE coverage
- `stride_completeness < 0.95` - Below recommended full STRIDE coverage
- `missing_categories_count > 5` - Too many missing categories may indicate incomplete analysis

---

## Error Handling

| Error | Cause | Recovery Action |
|-------|-------|-----------------|
| P2 YAML not found | P2 not completed | Return to P2, complete DFD analysis |
| P4 YAML not found | P4 not completed | Return to P4, complete security design review |
| DFD element missing threats | Incomplete analysis | Apply STRIDE matrix, generate minimum threats |
| CWE/CAPEC lookup failure | KB not available | Document without mapping, note limitation |
| Summary count mismatch | Calculation error | Recount threats[], update summary |

**Fallback Strategy**: If KB lookup fails, generate threats with manual CWE assignment based on STRIDE category. Mark `kb_lookup: failed` in threat metadata.

---

## Input Context

← P2: `dfd_elements` from `.phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml`
← P3: `boundary_context` from `.phase_working/{SESSION_ID}/data/P3_boundary_context.yaml`
← P4: `security_gaps` from `.phase_working/{SESSION_ID}/data/P4_security_gaps.yaml`

### ⚠️ MANDATORY: Query P2/P3/P4 Data Before Analysis

**Before starting P5 STRIDE analysis**, LLM MUST execute these queries to obtain upstream data:

```bash
# Step 1: Get P2 DFD elements (PRIMARY - REQUIRED for STRIDE)
python scripts/phase_data.py --query --phase 2 --type dfd --root .

# Step 2: Get P3 boundaries for severity amplification
python scripts/phase_data.py --query --phase 3 --summary --root .

# Step 3: Get P4 security gaps as threat triggers
python scripts/phase_data.py --query --phase 4 --type gaps --root .
```

**Or read YAML directly**:
```bash
# PRIMARY sources - ALL REQUIRED
cat .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
cat .phase_working/{SESSION_ID}/data/P3_boundary_context.yaml
cat .phase_working/{SESSION_ID}/data/P4_security_gaps.yaml
```

**CRITICAL**: STRIDE analysis MUST cover ALL P2 DFD elements. Do NOT skip elements or generate threats from memory!

**P3 Boundary Integration**:
- Consider trust boundary crossings when assessing threat severity
- Cross-boundary threats inherit higher initial_priority
- Use `boundaries[]` to identify attack surface exposure

## Output Context

→ P6: `threat_inventory` {threats[], summary{}}

---

## Core Analysis Goal

Apply STRIDE method systematically to ALL DFD elements, generating a complete threat inventory. Each element must be analyzed for applicable STRIDE categories.

---

## Knowledge Reference

**Query Commands**:
```bash
$SKILL_PATH/kb --stride spoofing           # STRIDE category details
$SKILL_PATH/kb --stride tampering
$SKILL_PATH/kb --full-chain CWE-89         # Complete chain: STRIDE→CWE→CAPEC→ATT&CK
$SKILL_PATH/kb --all-llm                   # LLM-specific threats
$SKILL_PATH/kb --cwe CWE-287               # Specific CWE details
$SKILL_PATH/kb --capec CWE-287             # CAPEC patterns for CWE
```

### KB Enrichment Log (MANDATORY per GAP-4 Contract)

> **CRITICAL**: P5 MUST query KB for CWE/CAPEC/ATT&CK mapping per KBQueryContract in assets/contracts/data-model.yaml

**Required Queries**:
1. `--cwe CWE-{NNN}` - For each threat's CWE classification
2. `--capec CWE-{NNN}` - For CAPEC attack pattern mapping
3. `--stride-mapping {S|T|R|I|D|E}` - For category-wide enrichment

```yaml
# In P5_threat_inventory.yaml - MANDATORY section (GAP-4 Contract)
kb_enrichment_log:
  # Query record for auditability
  queries_made:
    - query: "--stride-mapping S"
      timestamp: "2026-01-31T10:15:30Z"
      result_count: 25
      usage: "Informed spoofing threats T-S-*"
      cache_hit: false
    - query: "--cwe CWE-287"
      timestamp: "2026-01-31T10:15:45Z"
      result_count: 1
      usage: "Enriched T-S-P-001-001"
      cache_hit: true
    - query: "--capec CWE-287"
      timestamp: "2026-01-31T10:16:00Z"
      result_count: 3
      usage: "Mapped CAPEC-114, CAPEC-151, CAPEC-194"
      cache_hit: false

  # Enrichment tracking
  cwes_queried: [CWE-287, CWE-89, CWE-79, CWE-798, CWE-312]  # All unique CWEs
  capecs_mapped: [CAPEC-114, CAPEC-151, CAPEC-66, CAPEC-7]   # All CAPEC mappings
  attack_techniques: [T1078, T1190, T1059]                    # ATT&CK mappings

  # Coverage metrics (MANDATORY)
  enrichment_coverage:
    total_threats: 85
    threats_with_cwe: 78
    threats_with_capec: 65
    threats_with_attack: 45
    p0_p1_threats_total: 15
    p0_p1_with_cwe: 15          # MUST be 100% - ERROR if not
    coverage_percentage: 91.8    # threats_with_cwe / total_threats

  # Error tracking
  errors:
    - query: "--cwe CWE-9999"
      error_type: "not_found"
      action_taken: "Manual classification based on STRIDE category"
      affected_threats: [T-T-P-003-002]

  # KB availability status
  kb_available: true
  kb_version: "v4.19"           # CWE database version
```

**Validation Rules** (GAP-4 Contract):
- **ERROR**: Any P0/P1 threat without CWE mapping (`p0_p1_with_cwe < p0_p1_threats_total`)
- **WARNING**: `enrichment_coverage.coverage_percentage < 80%`
- **INFO**: All errors must be documented with `action_taken`

**Fallback Strategy**: If KB unavailable, set `kb_available: false` and use LLM knowledge for threat classification. Document limitation in errors[].

---

## ⚠️ STRIDE per Interaction (PRIMARY METHOD)

> **CRITICAL**: Use STRIDE per Interaction for systematic threat generation on data flows. This follows Microsoft TMT methodology where threats are generated based on **Source → Target** relationships.

### Interaction-Based Threat Generation

STRIDE per Interaction analyzes threats based on **who/what is interacting with whom/what**:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    STRIDE per Interaction Model                           │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   [Source Element] ──── Data Flow ───► [Target Element]                  │
│         ↓                    ↓                ↓                          │
│   Applicable:           Applicable:     Applicable:                       │
│   S (if external)        T, I, D        Full STRIDE                      │
│   R (if external)                       (based on type)                   │
│                                                                           │
│   Example:                                                                │
│   [User Browser] ─── DF-001 (HTTPS) ───► [API Gateway (P-001)]           │
│        EI-001                                  ↓                          │
│         ↓                            Target gets S,T,R,I,D,E              │
│   Source adds S,R                    Flow adds T,I,D                      │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

### Source → Target Threat Matrix

| Source Type | Target Type | Applicable STRIDE | Rationale |
|------------|-------------|-------------------|-----------|
| **ExternalInteractor** | Process | **S**, T, **R**, I, D, E | External actors may spoof identity, repudiate actions |
| ExternalInteractor | DataStore | T, R, I, D | Direct store access rarely allowed |
| **Process** | Process | T, R, I, D, E | Inter-process tampering, privilege escalation |
| Process | DataStore | **T**, R, **I**, **D** | Store integrity, confidentiality, availability |
| **DataStore** | Process | T, I | Data poisoning, information leakage |

### Data Flow Threat Inheritance

When analyzing a data flow, threats are inherited from:

```yaml
# Threat generation rule for DF-xxx
data_flow_threat_analysis:
  flow_id: DF-001
  source: EI-001  # External Interactor (User)
  target: P-001   # Process (API Gateway)
  trust_boundary_crossed: true  # Critical factor

  # Threats on the TARGET (P-001)
  target_threats:
    - S: "Spoofing - Source (EI-001) may spoof identity to Target"
    - T: "Tampering - Data from Source may be modified before reaching Target"
    - R: "Repudiation - Source (EI-001) may deny sending data"
    - I: "Information Disclosure - Target may leak sensitive data to unauthorized parties"
    - D: "Denial of Service - Target may be overwhelmed by Source requests"
    - E: "Elevation of Privilege - Attacker may gain higher privileges in Target"

  # Threats on the DATA FLOW itself (DF-001)
  flow_threats:
    - T: "Tampering - Data in transit may be modified"
    - I: "Information Disclosure - Data in transit may be intercepted"
    - D: "Denial of Service - Communication channel may be disrupted"

  # Threats from SOURCE perspective (EI-001)
  source_threats:
    - S: "Spoofing - External actor identity cannot be verified"
    - R: "Repudiation - External actor may deny actions"
```

### Trust Boundary Amplification

Threats crossing trust boundaries have elevated severity:

| Boundary Type | Severity Multiplier | Example |
|--------------|---------------------|---------|
| Internet ↔ DMZ | ×2.0 | Public API endpoint |
| DMZ ↔ Internal | ×1.5 | Internal service boundary |
| Internal ↔ Database | ×1.8 | Data tier access |
| Same Trust Zone | ×1.0 | No boundary crossing |

```yaml
# Example: Cross-boundary threat
threat_with_boundary:
  id: T-S-P-001-001
  element_id: P-001
  interaction:
    source: EI-001
    target: P-001
    flow: DF-001
    boundary_crossed: TB-001  # Internet → DMZ
  base_priority: P1
  boundary_multiplier: 2.0
  effective_priority: P0  # Elevated due to boundary
```

### Interaction Coverage Verification (REQUIRED)

**P5 MUST verify all interactions have STRIDE analysis**:

```yaml
# In P5_threat_inventory.yaml - REQUIRED section
interaction_coverage:
  # P2 Flow Input Reference
  p2_flow_ref: "P2_dfd_elements.yaml"

  # Total interactions analyzed
  total_interactions: 45           # Count of Source→Target pairs
  interactions_with_threats: 45    # All should have threats
  coverage_percentage: 100         # MUST be 100%

  # By boundary crossing
  cross_boundary_interactions:
    total: 12
    analyzed: 12
    coverage_percentage: 100       # BLOCKING if < 100%

  # Interaction detail
  interactions:
    - flow_id: DF-001
      source: EI-001
      target: P-001
      boundary_crossed: TB-001
      threats_generated: [T-S-P-001-001, T-T-DF-001-001, T-R-EI-001-001]
      stride_coverage: {S: 1, T: 1, R: 1, I: 0, D: 0, E: 0}
    - flow_id: DF-002
      source: P-001
      target: DS-001
      boundary_crossed: null
      threats_generated: [T-T-DS-001-001, T-I-DS-001-001]
      stride_coverage: {T: 1, I: 1, D: 0}
```

**Validation Rules**:
- **BLOCKING**: `coverage_percentage < 100%` (all interactions must be analyzed)
- **BLOCKING**: `cross_boundary_interactions.coverage_percentage < 100%` (boundary crossings are critical)
- **WARNING**: Any interaction with incomplete STRIDE coverage for its type

---

## STRIDE per Element Matrix (SECONDARY)

| Element Type | S | T | R | I | D | E |
|--------------|---|---|---|---|---|---|
| Process      | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data Store   |   | ✓ | ✓ | ✓ | ✓ |   |
| Data Flow    |   | ✓ |   | ✓ | ✓ |   |
| External Interactor (as source) | ✓ |   | ✓ |   |   |   |

### AI/LLM STRIDE Extensions

> When P4 triggers ext-13 (AI) or ext-16 (AGENT), apply these additional threat patterns.

| AI Element Type | S | T | R | I | D | E | Special Threats |
|-----------------|---|---|---|---|---|---|-----------------|
| LLM Gateway     | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Prompt injection, jailbreak |
| Model Endpoint  | ✓ | ✓ |   | ✓ | ✓ | ✓ | Model poisoning, adversarial input |
| RAG Pipeline    |   | ✓ |   | ✓ | ✓ |   | Context injection, data leakage |
| Agent Tool      | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Tool abuse, goal hijacking |

**AI-Specific CWE/CAPEC**:
- CWE-1039: Automatic Eval of Untrusted Data → CAPEC-676 (LLM Prompt Injection)
- CWE-1336: Object Injection → CAPEC-175 (Context Injection)
- CWE-20: Input Validation → CAPEC-242 (Adversarial Input)

---

## STRIDE Categories

### S - Spoofing

**Definition**: Impersonating something or someone

**CWE Mapping**: CWE-287, CWE-290, CWE-307
**CAPEC Mapping**: CAPEC-151, CAPEC-194, CAPEC-600

**Questions**:
- Can an attacker impersonate another user?
- Can an attacker impersonate a system component?
- Is authentication properly implemented?

### T - Tampering

**Definition**: Modifying data or code

**CWE Mapping**: CWE-20, CWE-77, CWE-78, CWE-89
**CAPEC Mapping**: CAPEC-66, CAPEC-88, CAPEC-248

**Questions**:
- Can input data be modified?
- Can stored data be modified?
- Can data in transit be modified?

### R - Repudiation

**Definition**: Denying having performed an action

**CWE Mapping**: CWE-117, CWE-223, CWE-778
**CAPEC Mapping**: CAPEC-93

**Questions**:
- Are actions logged?
- Can logs be modified or deleted?
- Is there sufficient audit trail?

### I - Information Disclosure

**Definition**: Exposing information to unauthorized parties

**CWE Mapping**: CWE-200, CWE-209, CWE-311
**CAPEC Mapping**: CAPEC-116, CAPEC-157

**Questions**:
- Can sensitive data be accessed?
- Are error messages revealing?
- Is data encrypted properly?

### D - Denial of Service

**Definition**: Making a resource unavailable

**CWE Mapping**: CWE-400, CWE-770, CWE-918
**CAPEC Mapping**: CAPEC-125, CAPEC-227

**Questions**:
- Can the service be overwhelmed?
- Are there resource limits?
- Can an attacker exhaust resources?

### E - Elevation of Privilege

**Definition**: Gaining unauthorized capabilities

**CWE Mapping**: CWE-269, CWE-284, CWE-862
**CAPEC Mapping**: CAPEC-122, CAPEC-233

**Questions**:
- Can a user gain admin privileges?
- Are authorization checks complete?
- Can an attacker escape sandbox?

---

## Threat ID Format

```
T-{STRIDE}-{ElementID}-{Seq}
```

- **STRIDE**: Single letter (S/T/R/I/D/E)
- **ElementID**: From P2 (e.g., P-001, DS-001, DF-001)
- **Seq**: Three-digit sequence (001-999)

**Examples**:
- `T-S-P-001-001` - First Spoofing threat for Process 001
- `T-T-DF-003-002` - Second Tampering threat for Data Flow 003
- `T-I-DS-001-001` - First Info Disclosure threat for Data Store 001

---

## Analysis Process

For each DFD element:

1. **Identify applicable STRIDE categories** (per matrix above)
2. **For each applicable category**:
   - Describe the threat scenario
   - Identify related CWE
   - Map to CAPEC if available
   - Assess initial priority

3. **Document in threat inventory**

---

## Threat Inventory Structure

```yaml:threat_inventory
threats:
  - id: T-S-P-001-001
    element_id: P-001
    element_name: "API Gateway"
    stride_type: S
    stride_name: Spoofing
    title: "Authentication Bypass via Token Manipulation"
    description: |
      An attacker could forge or manipulate JWT tokens to impersonate
      legitimate users or bypass authentication entirely.
    attack_scenario: |
      1. Attacker obtains a valid JWT token
      2. Modifies token payload (user_id, role)
      3. Server accepts modified token due to weak verification
    affected_flows: [DF-001, DF-002]
    affected_stores: []
    cwe: CWE-287
    capec: CAPEC-194
    initial_priority: P1
    likelihood: HIGH
    impact: HIGH

  - id: T-T-DS-001-001
    element_id: DS-001
    element_name: "User Database"
    stride_type: T
    stride_name: Tampering
    title: "SQL Injection in User Lookup"
    description: |
      User input in login query may allow SQL injection, enabling
      attackers to modify database contents.
    attack_scenario: |
      1. Attacker enters malicious input in username field
      2. Input concatenated into SQL query
      3. Attacker modifies or extracts database data
    affected_flows: [DF-003]
    affected_stores: [DS-001]
    cwe: CWE-89
    capec: CAPEC-66
    initial_priority: P0
    likelihood: MEDIUM
    impact: CRITICAL

summary:
  total: 85
  by_stride:
    S: 12
    T: 18
    R: 8
    I: 22
    D: 10
    E: 15
  by_element_type:
    process: 45
    datastore: 20
    dataflow: 15
    external: 5
  by_priority:
    P0: 5
    P1: 15
    P2: 35
    P3: 30
```

---

## Priority Classification

| CVSS Score | Priority | Action |
|------------|----------|--------|
| 9.0 - 10.0 | P0 | Immediate fix |
| 7.0 - 8.9 | P1 | Fix within 24h |
| 4.0 - 6.9 | P2 | Fix within 7d |
| 0.1 - 3.9 | P3 | Plan within 30d |

---

## Report Template

```markdown
# P5: STRIDE Threat Analysis

## Threat Summary

| Metric | Count |
|--------|-------|
| Total Threats | N |
| Critical (P0) | N |
| High (P1) | N |
| Medium (P2) | N |
| Low (P3) | N |

## STRIDE Distribution

| Category | Count | Percentage |
|----------|-------|------------|
| Spoofing | N | N% |
| Tampering | N | N% |
| Repudiation | N | N% |
| Information Disclosure | N | N% |
| Denial of Service | N | N% |
| Elevation of Privilege | N | N% |

## Element Coverage

| Element | Type | Threats |
|---------|------|---------|
| P-001 | Process | T-S-P-001-001, T-T-P-001-001, ... |
| DS-001 | Data Store | T-T-DS-001-001, T-I-DS-001-001, ... |
| DF-001 | Data Flow | T-T-DF-001-001, T-I-DF-001-001, ... |

## Threat Details

### T-S-P-001-001: Authentication Bypass via Token Manipulation

- **Element**: P-001 (API Gateway)
- **STRIDE**: Spoofing
- **CWE**: CWE-287
- **CAPEC**: CAPEC-194
- **Priority**: P1
- **Description**: ...
- **Attack Scenario**: ...

### T-T-DS-001-001: SQL Injection in User Lookup

...

## Threat Inventory

[yaml:threat_inventory block]
```

---

## Validation Gates

| Check | Severity |
|-------|----------|
| yaml:threat_inventory block present | BLOCKING |
| element_coverage_verification present | BLOCKING |
| Process coverage_percentage == 100% | BLOCKING |
| Data store coverage_percentage == 100% | BLOCKING |
| Data flow coverage_percentage == 100% | BLOCKING |
| External interactor coverage_percentage == 100% | BLOCKING |
| stride_completeness >= 0.80 | WARNING |
| Threat count per element >= 2 | WARNING |
| CWE mapping provided for each threat | WARNING |
| Summary totals match threat list | BLOCKING |

---

## Completion Checklist

Before marking Phase 5 complete:

**Element Coverage Verification**:
- [ ] `element_coverage_verification` section present in YAML
- [ ] Process coverage_percentage == 100%
- [ ] Data store coverage_percentage == 100%
- [ ] Data flow coverage_percentage == 100%
- [ ] External interactor coverage_percentage == 100%
- [ ] stride_completeness >= 0.80

**STRIDE Analysis**:
- [ ] All Processes analyzed for S,T,R,I,D,E
- [ ] All Data Stores analyzed for T,R,I,D
- [ ] All Data Flows analyzed for T,I,D
- [ ] All External Interactors analyzed for S,R
- [ ] yaml:threat_inventory block present
- [ ] Summary totals correct
- [ ] CWE/CAPEC mappings provided
- [ ] Validation passed

---

**End of Phase 5 Instructions** (~250 lines, ~2K tokens)
