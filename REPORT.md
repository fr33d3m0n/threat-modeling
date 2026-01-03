<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

# REPORT.md - Phase 7-8: Mitigation & Report Generation

> **Version**: 2.1.0
> **Scope**: 缓解措施生成 + 综合报告生成
> **Input**: P6 `validated_risks` (完整风险清单)
> **Output**: 4份必需报告 + 4份可选报告 + 阶段过程文档

---

## ⚠️ CRITICAL: Content Aggregation Requirements (内容聚合强制要求)

> **Root Cause Fix**: 此章节解决最终报告内容简陋、遗漏的根本原因

### 核心原则

**最终报告必须**:
1. **显式读取** 所有阶段文件（不依赖上下文记忆）
2. **完整复制** 风险详情、POC代码、攻击路径（不压缩、不总结）
3. **验证数量一致** 阶段文件中的条目数 = 最终报告中的条目数

### 禁止行为

❌ 使用 "详见附录" 或 "参见 Phase X" 等替代表述
❌ 省略低严重度风险的详情
❌ 仅列出风险名称和 ID 而不提供完整字段
❌ 依赖上下文记忆而非显式文件读取
❌ 对 POC 代码进行总结或压缩

---

## Phase 7: Mitigation Generation <ultrathink><critical thinking>

**Goal**: KB-enriched, technology-specific mitigation design with ASVS compliance verification.

**Must Use**:
- **Input**: `validated_risks` (complete Phase 6 output)
- **Security Control Set**: Control Sets + OWASP References + CWE Mitigations
- **Verification Set**: ASVS requirements for compliance verification

**Output File**: `.phase_working/P7-MITIGATION-PLANNING.md` (可选，如生成)

### For Each Risk (可并行启动子代理) <ultrathink><critical thinking>

1. **Query CWE mitigations**
   ```bash
   python scripts/unified_kb_query.py --cwe CWE-XXX --mitigations
   ```

2. **Query related CVE context**
   ```bash
   python scripts/unified_kb_query.py --cve-for-cwe CWE-XXX --cve-severity CRITICAL
   ```

3. **Get STRIDE control mapping**
   ```bash
   python scripts/unified_kb_query.py --stride [category]
   ```

4. **Query ASVS requirements for compliance**
   ```bash
   # Get ASVS requirements by level
   python scripts/unified_kb_query.py --asvs-level L2

   # Get ASVS requirements by chapter
   python scripts/unified_kb_query.py --asvs-chapter V4  # Access Control

   # Combined query for specific domain
   python scripts/unified_kb_query.py --asvs-level L2 --chapter V2  # Authentication
   ```

5. **Design technology-specific mitigation**
   - Map KB recommendations to project's tech stack
   - Ensure mitigation meets ASVS requirements at target level
   - Provide concrete implementation guidance
   - Include code examples where applicable

6. **Collect fix location information** ⚠️ NEW in v2.0.5
   For each mitigation, provide precise fix locations:
   - **模块定位**: Which module/package the fix applies to
   - **功能/类定位**: Specific function, class, or method name
   - **文件定位**: Exact file path in the codebase
   - **行号定位**: Line number or range (e.g., L45-L60)
   - **上下文代码**: Show 2 lines before/after the vulnerable code
   - **关联修复**: List related files that need coordinated changes

   ```yaml
   fix_location:
     module: "auth"
     function: "validateToken()"
     file: "src/middleware/auth.py"
     line_range: "45-52"
     context:
       before: ["def validateToken(token):", "    # Missing validation"]
       vulnerable: "    return True  # ← Always returns True!"
       after: ["", "def refreshToken(token):"]
     related_files:
       - file: "src/routes/api.py"
         line: 23
         change_type: "modify"
         description: "Add auth middleware to route"
   ```

7. **Define verification criteria**
   - Map to ASVS verification requirements
   - Include test cases from Phase 6 validation
   - Define acceptance criteria

7. **Estimate effort and prioritize**

### Parallel Sub-Agent Pattern <ultrathink><critical thinking>

```
Main Agent
    │
    ├──► VR-001 ──► Agent ──► CWE Mitigation + ASVS Query ──► Stack-Specific Design
    ├──► VR-002 ──► Agent ──► CVE Context + ASVS Chapter ──► Code Example
    └──► VR-003 ──► Agent ──► STRIDE Controls + ASVS Level ──► Implementation Plan
    │
    ◄───────────── Aggregate Results ──────────────
```

### Mitigation Output Template (with ASVS Compliance)

Phase 7 produces a `mitigation_plan` with ASVS compliance verification:

```yaml
mitigation_plan:
  # For each validated risk from Phase 6
  - risk_id: "VR-001"
    risk_summary: "Authentication bypass via unprotected endpoint"
    severity: critical
    cwe_refs: [CWE-287, CWE-306]

    # CWE Mitigations from KB
    kb_recommendations:
      - "Implement centralized authentication middleware"
      - "Use strong session management"
      - "Enable MFA for sensitive operations"

    # ASVS Compliance Requirements
    asvs_requirements:
      target_level: L2
      applicable_requirements:
        - id: "V2.1.1"
          description: "Verify user set passwords are at least 12 characters"
          chapter: V2-Authentication
          status: not_met
        - id: "V2.2.1"
          description: "Verify anti-automation controls are effective"
          chapter: V2-Authentication
          status: partial

    # Tiered Mitigation Actions
    immediate_actions:  # Quick fixes (hours)
      - action: "Block unprotected endpoint at WAF/gateway level"
        implementation: |
          # nginx configuration
          location /api/v2/user {
            auth_request /auth/verify;
          }
        effort: 1h
        risk_reduction: 80%

    short_term_fixes:  # Code changes (days)
      - action: "Add authentication middleware to all /api/v2 routes"
        control_ref: "control-set-01-authentication.md#centralized-auth"
        asvs_satisfies: ["V2.2.1", "V2.5.1"]

        # ⚠️ NEW in v2.0.5: Fix Location (修复定位)
        fix_location:
          primary:
            module: "middleware"
            function: "require_auth()"
            file: "src/middleware/auth.py"
            line_range: "1-15"  # For new file: entire file
          related:
            - file: "src/routes/api.py"
              line: 23
              change_type: "modify"
              description: "Apply @require_auth decorator"
            - file: "src/routes/user.py"
              line: 45
              change_type: "modify"
              description: "Apply @require_auth decorator"

        code_changes:
          - file: "src/middleware/auth.py"
            change_type: create
            content: |
              from functools import wraps
              def require_auth(f):
                  @wraps(f)
                  def decorated(*args, **kwargs):
                      token = request.headers.get('Authorization')
                      if not validate_token(token):
                          abort(401)
                      return f(*args, **kwargs)
                  return decorated
        effort: 2d

    long_term_improvements:  # Architectural (weeks)
      - action: "Implement centralized API gateway with built-in auth"
        asvs_satisfies: ["V2.1.1", "V2.2.1", "V2.5.1"]
        architecture_change: true
        effort: 2w

    # Verification Criteria
    verification_criteria:
      test_cases:
        - "All test cases from VR-001 validation pass"
      asvs_verification:
        - "V2.1.1: Password length >= 12 verified"
```

### Checkpoint (Phase 7)

Before proceeding to Phase 8, verify:
- [ ] Each risk has KB-enriched mitigation from `validated_risks`
- [ ] Technology-specific implementations provided with code examples
- [ ] **Fix location provided for each mitigation** (module, function, file, line) ⚠️ NEW
- [ ] **Related files listed for coordinated changes** ⚠️ NEW
- [ ] ASVS requirements mapped to each mitigation
- [ ] Effort estimated for each mitigation
- [ ] Implementation roadmap prioritized by severity and ASVS coverage
- [ ] Verification criteria defined with test cases

---

## Phase 8: Comprehensive Report <ultrathink><critical thinking>

**Goal**: Generate complete threat model report synthesizing ALL phases with full detail preservation.

**Must Use**:
- **Input**: ALL phase outputs (`findings_1` through `mitigation_plan`)
- **Knowledge**: Compliance Frameworks
- **Verification Set**: ASVS for compliance verification matrix
- **Templates**: `assets/templates/` directory (8 report templates)
- **Schemas**: `assets/schemas/` directory (data format definitions)

**⚠️ CRITICAL**: Phase 6 (`validated_risks`) outputs MUST be included in FULL DETAIL without omission or summarization.

---

### "FULL DETAIL" Definition (完整详情定义)

> **Reference**: `assets/schemas/risk-detail.schema.md` Section 5.1 Required Fields

"FULL DETAIL" 指每个风险必须包含以下所有必填字段:

| 类别 | 必填字段 | 说明 |
|------|---------|------|
| **Core** (5) | id, name, stride_category, element_id, element_name | 风险基本信息 |
| **Description** (2) | description.brief, description.detailed | 简述 + 详细描述 |
| **Location** (2) | location.component, location.file | 受影响组件和文件 |
| **Cause** (2) | cause_analysis.root_cause, cause_analysis.related_cwe | 根本原因 + CWE映射 |
| **Attack** (3) | attack_info.attack_path, attack_info.poc_method, attack_info.exploitability | 攻击路径 + POC + 可利用性 |
| **Impact** (4) | impact.confidentiality, impact.integrity, impact.availability, impact.cvss_score | CIA影响 + CVSS评分 |
| **Mitigation** (3) | mitigation.priority, mitigation.strategy, mitigation.short_term.description | 优先级 + 策略 + 短期措施 |

**共计**: 21 个必填字段，100% 完整率才算 "FULL DETAIL"

---

### Step 8.0: Mandatory File Reading (必需文件读取) ⚠️ NEW

**目标**: 在开始任何报告生成前，必须显式读取所有阶段产物文件到上下文。

**⚠️ 此步骤为必需步骤，不可跳过**

**执行动作**:

```yaml
mandatory_file_reads:
  # ════════════════════════════════════════════════════════════════════════════
  # Priority 0: 必须首先读取 (报告核心内容来源)
  # ════════════════════════════════════════════════════════════════════════════
  P0_critical:
    - file: ".phase_working/P6-RISK-VALIDATION.md"
      purpose: "风险详情、POC代码、攻击路径 - 最重要的内容来源"
      extract:
        - section: "risk_details[]"          # 所有 "### VR-XXX" 区块
        - section: "attack_paths[]"          # 所有攻击路径
        - section: "detailed_steps[]"        # 所有 POC 步骤
        - section: "poc_code"                # 所有 POC 代码块
      action: "READ_COMPLETE_FILE"

    - file: ".phase_working/P5-STRIDE-THREATS.md"
      purpose: "威胁清单、STRIDE分类 - 威胁识别来源"
      extract:
        - section: "threat_inventory[]"      # 所有 "T-X-XX-XXX" 条目
        - section: "stride_matrix"           # STRIDE 分布矩阵
      action: "READ_COMPLETE_FILE"

  # ════════════════════════════════════════════════════════════════════════════
  # Priority 1: 次要读取 (报告背景内容来源)
  # ════════════════════════════════════════════════════════════════════════════
  P1_important:
    - file: ".phase_working/P4-SECURITY-DESIGN-REVIEW.md"
      purpose: "安全设计差距"
      action: "READ_COMPLETE_FILE"

    - file: ".phase_working/P3-TRUST-BOUNDARY.md"
      purpose: "信任边界定义"
      action: "READ_COMPLETE_FILE"

  # ════════════════════════════════════════════════════════════════════════════
  # Priority 2: 背景读取 (项目上下文)
  # ════════════════════════════════════════════════════════════════════════════
  P2_context:
    - file: ".phase_working/P2-DFD-ANALYSIS.md"
      purpose: "DFD元素、数据流"
      action: "READ_COMPLETE_FILE"

    - file: ".phase_working/P1-PROJECT-UNDERSTANDING.md"
      purpose: "项目上下文"
      action: "READ_COMPLETE_FILE"
```

**验证检查**:
```
✅ P6-RISK-VALIDATION.md 已读取
✅ P5-STRIDE-THREATS.md 已读取
✅ P4-SECURITY-DESIGN-REVIEW.md 已读取
✅ P3-TRUST-BOUNDARY.md 已读取
✅ P2-DFD-ANALYSIS.md 已读取
✅ P1-PROJECT-UNDERSTANDING.md 已读取
```

**失败处理**: 如任何文件缺失，ABORT 并提示用户先完成相应阶段。

**输出**: 所有阶段内容已加载到上下文

---

### Step 8.1: Context Aggregation (上下文聚合)

**目标**: 基于 Step 8.0 读取的文件，构建完整风险清单。

**输入** (来自 Step 8.0 读取的文件):
- P1: project_context
- P2: dfd_elements
- P3: boundary_context
- P4: security_gaps
- P5: threat_inventory
- P6: validated_risks (核心)

**执行动作**:

1. **从 P6 提取风险清单**:
   - 识别所有 `### VR-XXX:` 或 `### Risk:` 区块
   - 计数: `count_p6_risks = N`

2. **从 P6 提取攻击路径**:
   - 识别所有 `### AP-XXX:` 或 `Attack Chain` 区块
   - 计数: `count_p6_paths = M`

3. **从 P6 提取 POC 代码**:
   - 识别所有 ` ```python`, ` ```bash` 代码块
   - 计数: `count_p6_pocs = K`

4. **记录计数以便后续验证**:
   ```yaml
   aggregation_counts:
     p6_risks: {N}
     p6_attack_paths: {M}
     p6_poc_blocks: {K}
   ```

**输出**: `aggregated_context` 包含完整的风险数据和计数

---

### Step 8.2: Content Source Mapping (内容来源映射) ⚠️ NEW

**目标**: 定义每份报告的每个章节必须从哪个阶段文件中 **COPY** (而非 summarize) 内容。

#### ⚠️ Traceability Preservation Rules (追溯性保留规则) ⚠️ CRITICAL

> **Core Principle**: 最终报告必须保留从 VR → Threat → Element 的完整追溯链

```yaml
traceability_rules:
  # ─────────────────────────────────────────────────────────────────────────
  # 规则 1: VR 必须包含 threat_refs
  # ─────────────────────────────────────────────────────────────────────────
  vr_threat_refs:
    requirement: "每个 VR 必须列出其 threat_refs[]"
    format: |
      ### VR-001: Plugin 任意代码执行
      **来源威胁**: T-T-P13-001, T-T-P13-002, T-E-P13-001  ← 必须包含
    example: |
      | VR ID | 来源威胁 (threat_refs) | 数量 |
      |-------|------------------------|------|
      | VR-001 | T-T-P13-001, T-T-P13-002, T-E-P13-001 | 3 |

  # ─────────────────────────────────────────────────────────────────────────
  # 规则 2: 保留原始 Threat ID 格式
  # ─────────────────────────────────────────────────────────────────────────
  threat_id_preservation:
    requirement: "禁止将 T-{STRIDE}-{Element}-{Seq} 转换为其他格式"
    forbidden:
      - "T-E-RCE-001"      # ❌ 不保留 ElementID
      - "RISK-001"          # ❌ 完全不同的格式
      - "T-T-EXEC-001"      # ❌ 使用描述性标识符
    allowed:
      - "T-T-P13-001"       # ✅ 保留 ElementID
      - "T-E-P13-001"       # ✅ 保留 ElementID

  # ─────────────────────────────────────────────────────────────────────────
  # 规则 3: 数量一致性
  # ─────────────────────────────────────────────────────────────────────────
  count_consistency:
    check: |
      P6 VR 数量 = RISK-INVENTORY VR 数量 = MAIN-REPORT 风险数量
    example: "8 VR = 8 条目 = 8 风险"
```

#### RISK-INVENTORY.md 内容映射

| 章节 | 来源文件 | 提取内容 | 动作 |
|------|---------|---------|------|
| 风险清单表 | P5-STRIDE-THREATS.md | 所有 `T-X-XX-XXX` 条目 | COPY ALL |
| 风险详细信息 | P6-RISK-VALIDATION.md | 所有 `### VR-XXX:` 区块 | COPY FULL BLOCKS |
| **⚠️ threat_refs 列** | P6-RISK-VALIDATION.md | 每个 VR 的 `threat_refs[]` | **COPY VERBATIM** |
| POC 代码 | P6-RISK-VALIDATION.md | 所有 ` ```python/bash 代码块 | COPY VERBATIM |
| 攻击路径 | P6-RISK-VALIDATION.md | 所有 `attack_path` 字段 | COPY ALL |
| 可行性矩阵 | P6-RISK-VALIDATION.md | `feasibility_assessment[]` | COPY ALL |

#### MITIGATION-MEASURES.md 内容映射

| 章节 | 来源文件 | 提取内容 | 动作 |
|------|---------|---------|------|
| 缓解措施表 | P6-RISK-VALIDATION.md | `mitigation.*` 字段 | COPY ALL |
| 优先级矩阵 | P6-RISK-VALIDATION.md | `priority` 字段 | AGGREGATE |
| 实施代码 | P6-RISK-VALIDATION.md | `mitigation.code` 字段 | COPY VERBATIM |
| ASVS 合规 | P6-RISK-VALIDATION.md | `asvs_requirements[]` | COPY ALL |

#### PENETRATION-TEST-PLAN.md 内容映射

| 章节 | 来源文件 | 提取内容 | 动作 |
|------|---------|---------|------|
| 测试用例 | P6-RISK-VALIDATION.md | `poc_method` 字段 | TRANSFORM → TC-X-XXX |
| POC 脚本 | P6-RISK-VALIDATION.md | 所有 POC 代码块 | COPY VERBATIM |
| 攻击链 | P6-RISK-VALIDATION.md | `attack_paths[]` 完整区块 | COPY ALL |
| ATT&CK 映射 | P6-RISK-VALIDATION.md | `attack_ids[]` 字段 | COPY ALL |

#### RISK-ASSESSMENT-REPORT.md 内容映射

| 章节 | 来源文件 | 提取内容 | 动作 |
|------|---------|---------|------|
| §1 执行摘要 | P6-RISK-VALIDATION.md | `risk_summary` | SUMMARIZE |
| §2 系统架构 | P1, P2 | 项目上下文、DFD | REFERENCE |
| §3 信任边界 | P3 | 边界定义 | REFERENCE |
| §4 安全设计 | P4 | 安全差距矩阵 | COPY |
| §5 威胁分析 | P5, P6 | 威胁清单、验证结果 | COPY ALL |
| §6 风险详情 | P6-RISK-VALIDATION.md | **所有 VR-XXX 完整区块** | **COPY FULL BLOCKS** |
| §7 攻击路径 | P6-RISK-VALIDATION.md | **所有攻击链图框** | **COPY VERBATIM** |
| §8 缓解建议 | P6-RISK-VALIDATION.md | `mitigation` 字段 | COPY ALL |
| §9 合规映射 | P6 | ASVS 矩阵 | COPY |

**⚠️ COPY 规则定义**:
- `COPY ALL`: 完整复制所有匹配项，不压缩不总结
- `COPY FULL BLOCKS`: 复制完整的 markdown 区块（包括子标题和所有内容）
- `COPY VERBATIM`: 逐字复制，包括代码格式、注释、空行
- `TRANSFORM`: 格式转换但保留全部信息量
- `SUMMARIZE`: 仅用于执行摘要章节
- `REFERENCE`: 引用并适当重组

---

### Step 8.3: Report Section Generation (章节生成)

**输入**: `aggregated_context` (from Step 8.1)

**按模板生成各报告章节** (遵循 Step 8.2 的内容映射):

1. Executive Summary (执行摘要)
2. Architecture Overview (架构概览) - from P1/P2
3. Security Design Assessment (安全设计评估) - from P4
4. STRIDE Threat Analysis (威胁分析) - COPY ALL from P5
5. Risk Details (风险详情) - **COPY FULL BLOCKS from P6**
6. Attack Path Analysis (攻击路径分析) - **COPY VERBATIM from P6**
7. Mitigation Recommendations (缓解建议) - COPY ALL from P6
8. Compliance Mapping (合规映射)
9. Appendices (附录)

**输出**: `report_sections{}`

---

### Step 8.4: Content Completeness Verification (内容完整性验证) ⚠️ NEW

**目标**: 确保最终报告包含阶段文件中的所有风险条目，无遗漏。

#### 8.4.1 Count Conservation Verification (数量守恒验证) ⚠️ CRITICAL

> **Source of Truth**: P6 的 `threat_disposition` 是数量验证的权威来源

```yaml
count_conservation_chain:
  # ═════════════════════════════════════════════════════════════════════════
  # 阶段 1: P5 → P6 威胁处理验证
  # ═════════════════════════════════════════════════════════════════════════
  p5_to_p6:
    input: "P5.threat_inventory.summary.total"     # 例: 120
    output_breakdown:
      consolidated: "sum(P6.VR.threat_refs.length)"  # 例: 98
      excluded: "len(P6.threat_disposition.excluded_threats)"  # 例: 22
    formula: "consolidated + excluded = input"
    example: "98 + 22 = 120 ✅"

  # ═════════════════════════════════════════════════════════════════════════
  # 阶段 2: P6 → 最终报告 VR 传递验证
  # ═════════════════════════════════════════════════════════════════════════
  p6_to_reports:
    source: "len(P6.validated_risks)"              # 例: 8 VR
    targets:
      risk_inventory: "COUNT(RISK-INVENTORY:VR-XXX)"
      main_report: "COUNT(MAIN-REPORT:风险详情)"
      pentest_plan: "COUNT(PENTEST-PLAN:test_cases)"
    formula: "source = risk_inventory = main_report"
    example: "8 = 8 = 8 ✅"

  # ═════════════════════════════════════════════════════════════════════════
  # 阶段 3: threat_refs 追溯验证
  # ═════════════════════════════════════════════════════════════════════════
  traceability_verification:
    check: |
      FOR each VR in RISK-INVENTORY:
        VR.threat_refs MUST NOT be empty
        VR.threat_refs values MUST match P5 threat IDs (T-{STRIDE}-{Element}-{Seq})
    on_fail: "ABORT - 追溯链断裂"
```

#### 8.4.2 Report Count Verification Matrix (报告数量验证矩阵)

| 检查项 | 来源计数 | 目标计数 | 验证方法 | 必须相等 |
|--------|---------|---------|---------|---------|
| VR 总数 | COUNT(P6:VR-XXX) | COUNT(RISK-INVENTORY:risks) | 计数比较 | ✅ 是 |
| threat_refs 总数 | sum(P6:VR.threat_refs) | P6.threat_disposition.consolidated | 计数比较 | ✅ 是 |
| POC代码块 | COUNT(P6:```code) | COUNT(PENTEST-PLAN:poc_scripts) | 计数比较 | ✅ 是 |
| 攻击路径 | COUNT(P6:AP-XXX) | COUNT(PENTEST-PLAN:attack_chains) | 计数比较 | ✅ 是 |
| 缓解措施 | COUNT(P6:mitigation) | COUNT(MITIGATION:measures) | 计数比较 | ✅ 是 |

**验证执行**:

```yaml
verification_checks:
  - check: "威胁数量守恒"
    priority: "CRITICAL"
    source: "P6.threat_disposition"
    validation: |
      consolidated_into_vr + excluded_with_reason = P5.total
    on_fail: "ABORT - 威胁丢失，无法生成报告"

  - check: "VR 数量一致"
    source: "P6-RISK-VALIDATION.md"
    source_pattern: "### VR-" 或 "### Risk:"
    target: "RISK-INVENTORY.md"
    target_section: "风险详细信息"
    action: |
      IF COUNT(source) != COUNT(target):
        1. 识别缺失的 VR-ID
        2. RE-READ P6 文件
        3. 补充缺失的风险区块到目标报告
        4. 重新验证直到通过

  - check: "threat_refs 完整"
    source: "P6.VR.threat_refs[]"
    target: "RISK-INVENTORY.VR.threat_refs[]"
    validation: |
      每个 VR 必须有非空的 threat_refs[]
      threat_refs 格式必须为 T-{STRIDE}-{Element}-{Seq}
    on_fail: "ABORT - 追溯链断裂"

  - check: "POC代码无遗漏"
    source: "P6-RISK-VALIDATION.md"
    source_pattern: "```python" 或 "```bash"
    target: "PENETRATION-TEST-PLAN.md"
    target_section: "POC 脚本"
    action: |
      IF COUNT(source) != COUNT(target):
        1. 识别缺失的代码块
        2. COPY VERBATIM 到目标报告
        3. 重新验证

  - check: "攻击链完整"
    source: "P6-RISK-VALIDATION.md"
    source_pattern: "### AP-" 或 "Attack Chain"
    target: "PENETRATION-TEST-PLAN.md"
    target_section: "攻击链分析"
    action: |
      IF COUNT(source) != COUNT(target):
        1. 识别缺失的攻击链
        2. COPY FULL BLOCKS 到目标报告
        3. 重新验证
```

**验证通过标准**:
- [ ] 威胁守恒: P5.total = consolidated + excluded ✅
- [ ] VR 数量: P6 = RISK-INVENTORY ✅
- [ ] threat_refs: 所有 VR 都有非空 threat_refs ✅
- [ ] POC数量: P6 = PENTEST-PLAN ✅
- [ ] 攻击路径: P6 = PENTEST-PLAN ✅
- [ ] 缓解措施: P6 = MITIGATION ✅

**验证失败处理**:
```
IF 威胁守恒失败:
    ABORT - 数据丢失，需检查 P6 threat_disposition

IF threat_refs 缺失:
    ABORT - 追溯链断裂，需修复 VR 结构

IF 其他检查失败:
    1. 输出详细的差异报告
    2. RE-READ 来源阶段文件
    3. 补充缺失内容
    4. 重复验证直到全部通过
```

**输出**: 验证通过确认 + 差异修复（如需）

---

### Step 8.5: Report Assembly (报告组装)

**输出目录**: `{PROJECT_ROOT}/Risk_Assessment_Report/`

```
{PROJECT_ROOT}/
└── Risk_Assessment_Report/           ← 最终报告目录
    ├── {PROJECT}-RISK-ASSESSMENT-REPORT.md
    ├── {PROJECT}-RISK-INVENTORY.md
    ├── {PROJECT}-MITIGATION-MEASURES.md
    ├── {PROJECT}-PENETRATION-TEST-PLAN.md
    └── ... (可选报告)
```

**8种标准报告定义**:

| # | 报告类型 | 文件名 | 模板文件 | 主要来源 | 必需 |
|---|----------|--------|----------|---------|------|
| 1 | 主报告 | `{PROJECT}-RISK-ASSESSMENT-REPORT.md` | `assets/templates/RISK-ASSESSMENT-REPORT.template.md` | P1-P8 全部 | ✅ |
| 2 | 风险清单 | `{PROJECT}-RISK-INVENTORY.md` | `assets/templates/RISK-INVENTORY.template.md` | P5, P6 | ✅ |
| 3 | 缓解措施 | `{PROJECT}-MITIGATION-MEASURES.md` | `assets/templates/MITIGATION-MEASURES.template.md` | P6, P7 | ✅ |
| 4 | 渗透计划 | `{PROJECT}-PENETRATION-TEST-PLAN.md` | `assets/templates/PENETRATION-TEST-PLAN.template.md` | P6 | ✅ |
| 5 | 架构分析 | `{PROJECT}-ARCHITECTURE-ANALYSIS.md` | `assets/templates/ARCHITECTURE-ANALYSIS.template.md` | P1, P2 | 可选 |
| 6 | DFD图 | `{PROJECT}-DFD-DIAGRAM.md` | `assets/templates/DFD-DIAGRAM.template.md` | P2, P3 | 可选 |
| 7 | 合规报告 | `{PROJECT}-COMPLIANCE-REPORT.md` | `assets/templates/COMPLIANCE-REPORT.template.md` | P5, P7 | 可选 |
| 8 | 攻击验证 | `{PROJECT}-ATTACK-PATH-VALIDATION.md` | `assets/templates/ATTACK-PATH-VALIDATION.template.md` | P6 | 可选 |

**报告生成步骤**:

1. **创建输出目录**: `mkdir -p {PROJECT_ROOT}/Risk_Assessment_Report/`
2. **确定PROJECT名称**: 从 project_context 提取，转换为大写
3. **按模板生成每份报告**: 引用 `assets/templates/` 目录对应模板
4. **验证文件命名**: 确保符合 `{PROJECT}-{REPORT_TYPE}.md` 格式

**输出**: 标准化报告文件集

---

### Step 8.6: Quality Validation (质量验证)

**质量检查清单 (Content Quality)**:
- [ ] 所有风险都有完整的5要素 (描述、位置、原因、攻击、缓解)
- [ ] 风险清单与详情块一一对应
- [ ] 统计数据准确 (总数、各级别数量、百分比)
- [ ] 报告格式符合模板结构
- [ ] 所有图表正确渲染 (ASCII, Mermaid)
- [ ] ASVS合规矩阵完整

**命名验证检查清单 (Naming Validation)**:

```
✅ PROJECT 名称验证:
   • 格式: 大写字母 + 数字 + 连字符
   • 正则: ^[A-Z][A-Z0-9-]{0,29}$
   • 示例: N8N, OPEN-WEBUI, MY-PROJECT-V2

✅ 文件名格式验证:
   • 格式: {PROJECT}-{REPORT_TYPE}.md
   • REPORT_TYPE 必须是8种标准类型之一

✅ 输出位置验证:
   • 必须位于: {PROJECT_ROOT}/Risk_Assessment_Report/
```

**验证脚本** (可选执行):
```bash
# 验证报告命名和位置
ls -la Risk_Assessment_Report/*.md

# 检查文件名格式
for f in Risk_Assessment_Report/*.md; do
  if [[ ! $(basename "$f") =~ ^[A-Z][A-Z0-9-]+-[A-Z-]+\.md$ ]]; then
    echo "INVALID: $f"
  fi
done
```

**输出**: 验证通过的最终报告集

---

### Step 8.7: Penetration Test Plan Generation (渗透测试方案生成) <ultrathink><critical thinking>

**目标**: 基于 P6 风险验证数据，生成详细的渗透测试方案。

**输入**:
- P6: `validated_risks[]` - 经过验证的风险清单
- P6: `attack_paths[]` - 攻击路径
- P6: `poc_methods[]` - POC 验证方法

**必需输出**: `{PROJECT}-PENETRATION-TEST-PLAN.md`

**模板**: `assets/templates/PENETRATION-TEST-PLAN.template.md`

#### 测试用例生成规则

**从 P6 风险验证数据映射测试用例**:

| P6 字段 | 测试用例字段 | 映射规则 |
|---------|-------------|---------|
| `risk.id` | `test_case.id` | TC-{STRIDE}-{SEQ} (e.g., TC-S-001) |
| `risk.name` | `test_case.objective` | 直接映射 |
| `risk.attack_path` | `test_case.steps` | 转换为测试步骤 |
| `risk.poc_method` | `test_case.poc_script` | **直接包含 (COPY VERBATIM)** |
| `risk.attack_info.attack_techniques` | `test_case.mitre_attack` | ATT&CK ID 映射 |
| `risk.priority` | `test_case.priority` | P0→Critical, P1→High, P2→Medium |
| `risk.location` | `test_case.target` | 目标组件/文件 |

#### ATT&CK 技术映射

| STRIDE | ATT&CK Tactic | 常见 Techniques |
|--------|--------------|-----------------|
| **S**poofing | Initial Access | T1078 (Valid Accounts), T1566 (Phishing) |
| **T**ampering | Impact | T1485 (Data Destruction), T1565 (Data Manipulation) |
| **R**epudiation | Defense Evasion | T1070 (Indicator Removal), T1036 (Masquerading) |
| **I**nfo Disclosure | Collection | T1005 (Data from Local System), T1039 (Data from Network) |
| **D**enial of Service | Impact | T1499 (Endpoint DoS), T1498 (Network DoS) |
| **E**levation | Privilege Escalation | T1068 (Exploitation), T1548 (Abuse Elevation) |

**输出**: `{PROJECT}-PENETRATION-TEST-PLAN.md`

---

### Step 8.8: Phase Output Publication (阶段产物发布) <ultrathink><critical thinking>

**目标**: 将阶段工作文档从隐藏目录复制到报告目录，作为完整交付物的一部分。

**⚠️ 此步骤为必需步骤，不可跳过**

**执行条件**: 在所有报告生成完成后执行

#### 文件发布清单

```yaml
source_directory: "{PROJECT_ROOT}/Risk_Assessment_Report/.phase_working/"
target_directory: "{PROJECT_ROOT}/Risk_Assessment_Report/"

files_to_publish:  # 保留英文文件名
  - P1-PROJECT-UNDERSTANDING.md    # Phase 1: 项目理解
  - P2-DFD-ANALYSIS.md             # Phase 2: DFD分析
  - P3-TRUST-BOUNDARY.md           # Phase 3: 信任边界
  - P4-SECURITY-DESIGN-REVIEW.md   # Phase 4: 安全设计评估
  - P5-STRIDE-THREATS.md           # Phase 5: STRIDE威胁分析
  - P6-RISK-VALIDATION.md          # Phase 6: 风险验证
```

#### 执行命令

```bash
# 复制阶段过程文档到报告目录 (保留英文名)
cd {PROJECT_ROOT}/Risk_Assessment_Report/

cp .phase_working/P1-PROJECT-UNDERSTANDING.md ./
cp .phase_working/P2-DFD-ANALYSIS.md ./
cp .phase_working/P3-TRUST-BOUNDARY.md ./
cp .phase_working/P4-SECURITY-DESIGN-REVIEW.md ./
cp .phase_working/P5-STRIDE-THREATS.md ./
cp .phase_working/P6-RISK-VALIDATION.md ./
```

#### 最终目录结构

```
{PROJECT_ROOT}/Risk_Assessment_Report/
├── {PROJECT}-RISK-ASSESSMENT-REPORT.md    ← 必需报告 (主报告)
├── {PROJECT}-RISK-INVENTORY.md            ← 必需报告
├── {PROJECT}-MITIGATION-MEASURES.md       ← 必需报告
├── {PROJECT}-PENETRATION-TEST-PLAN.md     ← 必需报告
├── P1-PROJECT-UNDERSTANDING.md            ← 阶段文档
├── P2-DFD-ANALYSIS.md                     ← 阶段文档
├── P3-TRUST-BOUNDARY.md                   ← 阶段文档
├── P4-SECURITY-DESIGN-REVIEW.md           ← 阶段文档
├── P5-STRIDE-THREATS.md                   ← 阶段文档
├── P6-RISK-VALIDATION.md                  ← 阶段文档
└── .phase_working/                        ← 工作目录 (保留)
    └── ...
```

**价值说明**:
- 阶段过程文档记录完整分析推导过程
- 支持审计追溯和质量验证
- 便于团队理解威胁建模逻辑链
- 保留英文名确保与命名规范一致

**输出**: 完整的阶段文档集发布到报告目录

---

## Output Files

**输出目录**: `{PROJECT_ROOT}/Risk_Assessment_Report/`

**主报告**: `{PROJECT}-RISK-ASSESSMENT-REPORT.md` - 完整威胁模型报告

**必需报告集** (始终生成):
| 序号 | 文件名 | 说明 |
|------|--------|------|
| 1 | `{PROJECT}-RISK-ASSESSMENT-REPORT.md` | 风险评估报告 (主报告) |
| 2 | `{PROJECT}-RISK-INVENTORY.md` | 风险清单 |
| 3 | `{PROJECT}-MITIGATION-MEASURES.md` | 缓解措施 |
| 4 | `{PROJECT}-PENETRATION-TEST-PLAN.md` | 渗透测试方案 |

**可选报告集** (按需生成):
| 序号 | 文件名 | 说明 |
|------|--------|------|
| 5 | `{PROJECT}-ARCHITECTURE-ANALYSIS.md` | 架构分析 |
| 6 | `{PROJECT}-DFD-DIAGRAM.md` | DFD图 |
| 7 | `{PROJECT}-COMPLIANCE-REPORT.md` | 合规报告 |
| 8 | `{PROJECT}-ATTACK-PATH-VALIDATION.md` | 攻击路径验证 |

**阶段过程文档** (自动发布):
| 序号 | 文件名 | 说明 |
|------|--------|------|
| - | `P1-PROJECT-UNDERSTANDING.md` | Phase 1 项目理解 |
| - | `P2-DFD-ANALYSIS.md` | Phase 2 DFD分析 |
| - | `P3-TRUST-BOUNDARY.md` | Phase 3 信任边界 |
| - | `P4-SECURITY-DESIGN-REVIEW.md` | Phase 4 安全设计评估 |
| - | `P5-STRIDE-THREATS.md` | Phase 5 STRIDE威胁分析 |
| - | `P6-RISK-VALIDATION.md` | Phase 6 风险验证 |

**模板位置**: `assets/templates/` 目录包含 8 个报告模板文件

**Schema 位置**: `assets/schemas/` 目录包含数据格式定义

---

## Final Checkpoint

Before completing Phase 8, verify:
- [ ] Step 8.0: 所有阶段文件已显式读取
- [ ] Step 8.1: 风险计数已记录 (P6_risks = N)
- [ ] Step 8.2: 内容来源映射已遵循
- [ ] Step 8.3: 报告章节已生成
- [ ] Step 8.4: 内容完整性验证已通过 (P6 = 最终报告)
- [ ] Step 8.5: 4份必需报告已生成
- [ ] Step 8.6: 质量验证已通过
- [ ] Step 8.7: 渗透测试方案已生成 (包含所有POC)
- [ ] Step 8.8: 阶段产物已发布

**Reflection**: Review all reports for completeness. Ensure NO risk details, POC code, or attack paths were omitted or summarized.
