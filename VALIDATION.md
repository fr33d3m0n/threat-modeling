# VALIDATION.md - Phase 6: Risk Validation (风险验证)

> **Version**: 2.0.4
> **Scope**: 风险验证、攻击路径分析、POC设计
> **Input**: P1-P5 所有阶段产物
> **Output**: `validated_risks` 完整风险清单 + POC验证

---

## Phase 6: Risk Validation <ultrathink><critical thinking>

**Goal**: Comprehensive risk validation with attack path verification, POC design, and Verification Set integration.

**Must Use**:
- **ALL previous findings**: `findings_1` + `findings_2` + `findings_3` + `findings_4` + `findings_5`
- **Threat Pattern Set**: CAPEC → ATT&CK → CVE/KEV
- **Verification Set**: WSTG/MASTG test procedures

**Output File**: `.phase_working/P6-RISK-VALIDATION.md`

---

## Consolidation Process (合并算法)

Phase 6 的首要任务是将 P1-P5 的所有安全发现合并为统一的风险清单，避免重复并保持可追溯性。

### Step 6.1: 收集所有发现

**⚠️ MANDATORY FILE READS** (必须执行的文件读取):

```yaml
input_sources:
  - source: ".phase_working/P1-PROJECT-UNDERSTANDING.md"
    extract_section: "初步安全观察" | "Initial Security Observations"
    id_prefix: SF-P1
    expected_fields: [description, component, severity_hint]

  - source: ".phase_working/P2-DFD-ANALYSIS.md"
    extract_section: "数据流风险" | "Data Flow Risks"
    id_prefix: SF-P2
    expected_fields: [description, element_id, data_sensitivity]

  - source: ".phase_working/P3-TRUST-BOUNDARY.md"
    extract_section: "边界风险" | "Boundary Risks"
    id_prefix: SF-P3
    expected_fields: [description, boundary_id, crossing_type]

  - source: ".phase_working/P4-SECURITY-DESIGN-REVIEW.md"
    extract_section: "安全差距" | "Security Gaps"
    id_prefix: SF-P4
    expected_fields: [domain, gap_description, current_status, risk_level]

  - source: ".phase_working/P5-STRIDE-THREATS.md"
    extract_section: "威胁清单" | "Threat Inventory"
    id_prefix: T-{STRIDE}
    expected_fields: [id, stride_category, element_id, description, cwe, priority]
```

### Step 6.2: 标准化为统一格式

将所有发现转换为 `normalized_finding` 中间格式：

```yaml
normalized_finding:
  # === 标识信息 ===
  original_id: "SF-P3-001"              # 原始ID (必需)
  source_phase: "P3"                    # 来源阶段 (必需)

  # === 匹配键 (用于去重) ===
  related_cwe: "CWE-287"                # 主匹配键1 (必需，如缺失则推断或标记UNKNOWN)
  location_file: "src/api/routes.py"    # 主匹配键2 (必需，标准化为相对路径)
  location_component: "api"             # 辅助匹配键 (模块级别)

  # === 分类信息 ===
  stride_category: "S"                  # STRIDE分类 (如果是SF需推断)

  # === 严重度 ===
  severity: "high"                      # 统一为: critical/high/medium/low
  cvss_estimate: 7.5                    # CVSS估算 (如有)

  # === 描述信息 ===
  description_brief: "认证缺失..."      # 简述 (用于备用匹配)
  description_full: "..."               # 完整描述

# === CWE 推断规则 (当原始发现缺少CWE时) ===
cwe_inference:
  rules:
    - pattern: "认证|authentication|login|credential"
      infer_cwe: "CWE-287"
    - pattern: "授权|authorization|access control|permission"
      infer_cwe: "CWE-863"
    - pattern: "注入|injection|SQL|XSS|command"
      infer_cwe: "CWE-74"
    - pattern: "加密|encryption|crypto|secret|key"
      infer_cwe: "CWE-327"
    - pattern: "日志|logging|audit|repudiation"
      infer_cwe: "CWE-778"
  fallback: "CWE-UNKNOWN"  # 无法推断时标记

# === 路径标准化规则 ===
path_normalization:
  - remove_prefix: ["/home/", "~/", "./"]
  - use_forward_slash: true
  - lowercase: false  # 保留大小写
  - remove_trailing_slash: true
```

### Step 6.3: 去重匹配规则

```yaml
deduplication_rules:
  # ─────────────────────────────────────────────────────────────────────────
  # 规则1: 精确匹配 (同一问题的不同视角)
  # ─────────────────────────────────────────────────────────────────────────
  exact_match:
    name: "MERGE - 精确匹配"
    criteria:
      - related_cwe: EQUAL
      - location_file: EQUAL
    action: MERGE

    merge_strategy:
      # ID处理: 生成新的VR-ID，保留所有原始ID
      new_id_format: "VR-{SEQ:03d}"
      original_ids: COLLECT_ALL  # → original_refs: ["SF-P3-001", "T-S-P01-001"]

      # 严重度: 取最高
      severity: MAX
      cvss: MAX

      # 描述: 合并并标注来源
      description: |
        [Consolidated from {count} findings]

        Source P{X}: {description_1}
        Source P{Y}: {description_2}
        ...

      # CWE: 优先使用P5的CWE (最权威)
      cwe_priority: [P5, P4, P3, P2, P1]

      # STRIDE: 优先使用P5的分类
      stride_priority: [P5, P4, P3, P2, P1]

  # ─────────────────────────────────────────────────────────────────────────
  # 规则2: 组件级匹配 (相关但不同的问题)
  # ─────────────────────────────────────────────────────────────────────────
  component_match:
    name: "LINK - 组件级匹配"
    criteria:
      - related_cwe: EQUAL
      - location_component: EQUAL
      - location_file: NOT_EQUAL
    action: LINK

    link_strategy:
      # 保持为独立风险
      keep_separate: true

      # 建立关联关系
      add_field: "related_risks"
      link_type: "same_cwe_same_component"

      # 各自保持独立VR-ID
      each_gets_vr_id: true

  # ─────────────────────────────────────────────────────────────────────────
  # 规则3: 描述相似度匹配 (备用规则 - 当CWE或文件缺失时)
  # ─────────────────────────────────────────────────────────────────────────
  description_similarity:
    name: "LINK - 描述相似"
    trigger: "当 related_cwe = 'CWE-UNKNOWN' 或 location_file 为空"
    criteria:
      - description_similarity: >= 0.85  # 使用编辑距离或语义相似度
      - location_component: EQUAL  # 至少组件相同
    action: LINK  # 不自动MERGE，需人工确认

    link_strategy:
      keep_separate: true
      add_field: "possibly_related"
      requires_review: true  # 标记需要人工确认
      similarity_score: RECORD  # 记录相似度分数

  # ─────────────────────────────────────────────────────────────────────────
  # 规则4: 无匹配
  # ─────────────────────────────────────────────────────────────────────────
  no_match:
    name: "KEEP - 独立风险"
    action: KEEP_AS_IS

    strategy:
      assign_vr_id: true
      mark_as: "standalone"
```

### Step 6.4: 严重度统一映射

```yaml
severity_normalization:
  # 输入格式统一化
  input_mapping:
    critical: critical
    high: high
    medium: medium
    low: low
    # 变体映射
    严重: critical
    高: high
    中: medium
    低: low
    P0: critical
    P1: high
    P2: medium
    P3: low
    "9.0-10.0": critical
    "7.0-8.9": high
    "4.0-6.9": medium
    "0.1-3.9": low

  # MAX 策略实现
  severity_order: [critical, high, medium, low]  # 索引越小越严重
  max_logic: "取 severity_order 中索引最小的值"
```

### Step 6.5: 生成验证风险ID

```yaml
validated_risk_id_schema:
  format: "VR-{SEQ:03d}"
  examples: ["VR-001", "VR-002", "VR-003"]

  sequence_rules:
    start_from: 1
    increment: 1
    ordering: "按严重度降序 (critical → low)"

  # ═════════════════════════════════════════════════════════════════════════
  # ⚠️ CRITICAL: threat_refs[] 是必填字段！
  # ═════════════════════════════════════════════════════════════════════════
  required_fields:
    - vr_id: "VR-001"
    - threat_refs: ["T-T-P13-001", "T-T-P13-002"]  # ⚠️ MANDATORY: 威胁来源列表
    - finding_refs: ["F-P4-003"]  # OPTIONAL: P1-P4 发现来源
    - merge_type: "exact_match" | "component_match" | "standalone"
    - merged_count: 2  # 合并了几个威胁
    - canonical_cwe: "CWE-287"  # 权威CWE
    - canonical_file: "src/api/routes.py"  # 代表性文件
    - stride_category: "S"
    - severity: "high"
    - cvss_score: 7.5

# 输出示例 (符合新数据模型)
validated_risk_example:
  vr_id: "VR-001"
  threat_refs: ["T-T-P13-001", "T-T-P13-002", "T-E-P13-001"]  # ⚠️ 关键: 追溯原始威胁
  finding_refs: ["F-P4-003"]
  merge_type: "exact_match"
  merged_count: 3
  canonical_cwe: "CWE-94"
  canonical_file: "utils/plugin.py"
  stride_categories: ["T", "E"]  # 合并后可包含多个 STRIDE 类型
  severity: "critical"
  cvss_score: 10.0
  description_brief: "Plugin 任意代码执行"
  description_full: |
    [Consolidated from 3 threats]

    Source T-T-P13-001: Plugin 代码注入 (Tampering)
    Source T-T-P13-002: pip 供应链攻击 (Tampering)
    Source T-E-P13-001: 权限提升至服务器控制 (Elevation)
```

### Step 6.5.1: Threat Disposition Tracking (威胁处理追踪) ⚠️ NEW

> **Purpose**: 确保每个 P5 威胁都被明确处理，支持数量守恒验证

```yaml
# ═════════════════════════════════════════════════════════════════════════
# 威胁处理追踪表 - 必须在 P6 输出中包含
# ═════════════════════════════════════════════════════════════════════════
threat_disposition:
  # ─────────────────────────────────────────────────────────────────────────
  # 统计汇总
  # ─────────────────────────────────────────────────────────────────────────
  input_count: 120                # 来自 P5 的威胁总数
  output_summary:
    consolidated_into_vr: 98      # 合并到 VR 的威胁数
    excluded_with_reason: 22      # 排除的威胁数 (需给出理由)
    validation_formula: "98 + 22 = 120 ✅"

  # ─────────────────────────────────────────────────────────────────────────
  # 按 VR 分组的威胁来源
  # ─────────────────────────────────────────────────────────────────────────
  vr_threat_mapping:
    VR-001:
      threat_refs: ["T-T-P13-001", "T-T-P13-002", "T-E-P13-001"]
      count: 3
    VR-002:
      threat_refs: ["T-S-P01-001", "T-S-P01-002"]
      count: 2
    VR-003:
      threat_refs: ["T-I-DS01-001"]
      count: 1
    # ... 每个 VR 都必须列出其 threat_refs

  # ─────────────────────────────────────────────────────────────────────────
  # 排除的威胁 (必须说明理由)
  # ─────────────────────────────────────────────────────────────────────────
  excluded_threats:
    - threat_id: "T-D-P07-001"
      reason: "MITIGATED - 已有 rate limiting 控制 (routers/auths.py:45)"
      status: "mitigated"
    - threat_id: "T-S-P02-002"
      reason: "MITIGATED - escape_filter_chars() 已应用 (auths.py:298)"
      status: "mitigated"
    - threat_id: "T-I-DF15-003"
      reason: "LOW_RISK - 理论可行但需物理访问"
      status: "excluded_low_risk"

  # ─────────────────────────────────────────────────────────────────────────
  # 验证规则
  # ─────────────────────────────────────────────────────────────────────────
  validation_rules:
    - rule: "每个 P5 威胁必须出现在某个 VR.threat_refs 或 excluded_threats 中"
      formula: "sum(vr_threat_mapping.*.count) + len(excluded_threats) = input_count"
    - rule: "excluded_threats 必须有 reason 字段"
      formula: "all(excluded_threats.*.reason != null)"
```

**P6 输出必须包含**:
1. `threat_disposition.input_count` - 来自 P5 的威胁总数
2. `threat_disposition.vr_threat_mapping` - 每个 VR 的威胁来源
3. `threat_disposition.excluded_threats` - 排除的威胁及理由
4. `threat_disposition.validation_formula` - 数量守恒验证

### Step 6.6: 完整性验证

```yaml
completeness_verification:
  # ═════════════════════════════════════════════════════════════════════════
  # 1. P5 威胁处理验证 (核心验证) ⚠️ CRITICAL
  # ═════════════════════════════════════════════════════════════════════════
  p5_threat_verification:
    input_count: "P5.threat_inventory.summary.total"  # 例: 120
    output_breakdown:
      consolidated_into_vr: "sum(all VR.threat_refs.length)"  # 例: 98
      excluded_with_reason: "len(threat_disposition.excluded_threats)"  # 例: 22

    conservation_formula: |
      consolidated_into_vr + excluded_with_reason = input_count
      例: 98 + 22 = 120 ✅

    validation_rules:
      - name: "威胁数量守恒"
        formula: "consolidated + excluded = P5_total"
        on_fail: "ABORT - 威胁丢失，检查 threat_disposition"

      - name: "每个威胁有归属"
        check: |
          FOR each threat T in P5.threat_inventory.threats:
            T.id MUST appear in:
              - some VR.threat_refs[], OR
              - threat_disposition.excluded_threats[]
        on_fail: "ABORT - 威胁 {T.id} 未被处理"

      - name: "排除威胁有理由"
        formula: "all(excluded_threats.*.reason != null)"
        on_fail: "WARNING - 排除的威胁缺少理由"

  # ═════════════════════════════════════════════════════════════════════════
  # 2. VR 结构验证
  # ═════════════════════════════════════════════════════════════════════════
  vr_structure_verification:
    checks:
      - name: "所有VR有threat_refs"
        formula: "all(VR.threat_refs.length > 0)"
        on_fail: "ABORT - VR 必须有 threat_refs[]"

      - name: "无重复VR-ID"
        formula: "count(unique(vr_ids)) == len(vr_ids)"
        on_fail: "ABORT - VR-ID 冲突"

      - name: "所有VR有CWE"
        formula: "all(VR.canonical_cwe != null)"
        on_fail: "WARNING - 部分VR缺少CWE"

  # ═════════════════════════════════════════════════════════════════════════
  # 3. 输出汇总 (必须包含在 P6 报告中)
  # ═════════════════════════════════════════════════════════════════════════
  consolidation_summary:
    template: |
      ## Phase 6 威胁处理汇总

      ### P5 输入
      | 来源 | 数量 |
      |------|------|
      | P5 威胁总数 | **{P5_total}** |

      ### 处理结果
      | 处理类型 | 数量 | 百分比 |
      |---------|------|--------|
      | 合并到 VR | {consolidated} | {consolidated/P5_total*100}% |
      | 排除 (已缓解/低风险) | {excluded} | {excluded/P5_total*100}% |
      | **总计** | **{P5_total}** | 100% |

      ### VR 生成统计
      | 指标 | 值 |
      |------|-----|
      | 生成的 VR 数量 | {VR_count} |
      | 平均每 VR 合并威胁数 | {consolidated/VR_count} |

      ### ⚠️ 数量守恒验证
      ```
      P5 威胁总数: {P5_total}
      = 合并到 VR ({consolidated}) + 排除 ({excluded})
      = {consolidated} + {excluded}
      ✅ 验证通过
      ```

      ### threat_refs 追溯示例
      | VR ID | 来源威胁 | 数量 |
      |-------|---------|------|
      | VR-001 | T-T-P13-001, T-T-P13-002, T-E-P13-001 | 3 |
      | VR-002 | T-S-P01-001, T-S-P01-002 | 2 |
      | ... | ... | ... |
```

**⚠️ 验证失败处理**:
- 数量守恒失败 → 立即 ABORT，检查 threat_disposition
- threat_refs 缺失 → 立即 ABORT，VR 无法追溯
- 排除理由缺失 → WARNING，继续但标记

---

## For Each Risk (可并行启动子代理) <ultrathink><critical thinking>

1. **Query CAPEC attack patterns**
   ```bash
   python scripts/unified_kb_query.py --capec CAPEC-XXX --attack-chain
   ```

2. **Query ATT&CK techniques**
   ```bash
   python scripts/unified_kb_query.py --attack-technique TXXX
   ```

3. **Check for known exploited vulnerabilities**
   ```bash
   python scripts/unified_kb_query.py --check-kev CVE-XXXX
   python scripts/unified_kb_query.py --cve-for-cwe CWE-XXX
   ```

4. **Query Verification Set for test procedures** (NEW in v2.0)
   ```bash
   # Get STRIDE-specific tests
   python scripts/unified_kb_query.py --stride-tests S

   # Get CWE-specific tests
   python scripts/unified_kb_query.py --cwe-tests CWE-89

   # Get WSTG category tests
   python scripts/unified_kb_query.py --wstg-category ATHN
   ```

5. **Construct attack path**
   - Entry point → Step 1 → Step 2 → ... → Impact
   - Identify prerequisites and conditions
   - Include ATT&CK technique references

6. **Design POC verification approach**
   - Generate test cases from `verification_procedure` table
   - Manual testing steps with commands
   - Automated testing with expected results
   - Tools required

### Parallel Sub-Agent Pattern <ultrathink><critical thinking>

```
Main Agent
    │
    ├──► T-S-P1-001 ──► Agent ──► CAPEC Query + ATT&CK Query + STRIDE Tests ──► Attack Path
    ├──► T-T-DF1-001 ──► Agent ──► CAPEC Query + KEV Check + CWE Tests ──► POC Design
    └──► T-E-P3-001 ──► Agent ──► CAPEC Query + CVE Search + WSTG Tests ──► Verification
    │
    ◄───────────── Aggregate Results ──────────────
```

---

## Risk Validation Output Template (5-Part Structure)

Phase 6 produces a comprehensive `validated_risks` output with 5 distinct parts:

```yaml
validated_risks:
  # ─────────────────────────────────────────────────────────────────
  # Part 1: Risk Summary (Assessment Overview)
  # ─────────────────────────────────────────────────────────────────
  risk_summary:
    total_identified: 45
    validated_high: 12
    validated_medium: 18
    validated_low: 10
    dismissed: 5
    risk_by_stride: {S: 8, T: 12, R: 3, I: 10, D: 4, E: 8}
    risk_by_domain: {AUTHN: 10, INPUT: 15, AUTHZ: 8, API: 6, CRYPTO: 4, DATA: 2}

  # ─────────────────────────────────────────────────────────────────
  # Part 2: Detailed Risk Analysis (Per-Item Analysis)
  # ─────────────────────────────────────────────────────────────────
  risk_details:
    - risk_id: "VR-001"
      original_refs: ["T-S-P1-001", "SD-001", "DFD-002"]  # Consolidated sources
      stride_category: S
      severity: critical

      # 2.1 Issue Location
      location:
        files: ["src/auth/login.py:45-67", "src/api/handlers.py:120"]
        elements: ["P1:AuthService", "DF-3:UserCredentials"]
        trust_boundary: "TB-1:Internet/DMZ"

      # 2.2 Detailed Analysis
      detailed_analysis:
        vulnerability_type: "CWE-287 Improper Authentication"
        cwe_ids: [CWE-287, CWE-306]
        capec_ids: [CAPEC-151, CAPEC-600]
        attack_ids: [T1110, T1078]
        description: "Authentication bypass possible via unprotected endpoint"
        technical_details: "The login function at line 45 accepts..."
        attack_surface: "External, unauthenticated"
        affected_data: ["user_credentials", "session_tokens"]
        impact: "Complete authentication bypass, account takeover"

      # 2.3 Root Cause Analysis
      root_cause:
        primary_cause: "Missing authentication check on /api/v2 endpoint"
        contributing_factors:
          - "No centralized authentication middleware"
          - "Inconsistent route protection patterns"
        design_flaw: true
        implementation_flaw: true
        cwe_chain: [CWE-287, CWE-863]

      # 2.4 Test Cases / POC (from Verification Set)
      validation:
        verification_tests:  # From WSTG/MASTG
          - test_id: "WSTG-ATHN-01"
            name: "Test for Credentials Transported over Encrypted Channel"
            result: FAIL
          - test_id: "WSTG-ATHN-04"
            name: "Testing for Bypassing Authentication Schema"
            result: FAIL
        test_cases:
          - name: "TC-001: Direct endpoint access"
            method: "GET /api/v2/user/profile without token"
            expected: "401 Unauthorized"
            actual: "200 OK with user data"
            result: FAIL
        poc_available: true
        poc_complexity: low
        cvss_score: 9.1
        kev_status: false

      # 2.5 Mitigation Outline (Phase 7 细化)
      mitigation:
        priority: "P0"
        strategy: "Implement centralized authentication middleware"
        short_term:
          description: "Add auth check to /api/v2 routes"
          estimated_effort: "2 days"
        long_term:
          description: "Implement API gateway with built-in auth"
          estimated_effort: "2 weeks"

  # ─────────────────────────────────────────────────────────────────
  # Part 3: Attack Path Analysis
  # ─────────────────────────────────────────────────────────────────
  attack_paths:
    - path_id: "AP-001"
      name: "Authentication Bypass to Data Exfiltration"
      risk_refs: ["VR-001", "VR-005", "VR-012"]
      description: "Attacker chains authentication bypass with data access"

      # 3.1 Attack Chain Summary
      attack_chain:
        entry_point: "External:Internet"
        target: "DataStore:UserDatabase"
        trust_boundaries_crossed: ["TB-1", "TB-2"]
        techniques_used:
          - capec: CAPEC-151
            attack: T1078
            description: "Identity Spoofing via authentication bypass"
          - capec: CAPEC-116
            attack: T1552
            description: "Credential extraction from memory"

      overall_complexity: medium
      detection_difficulty: high
      business_impact: critical

      # ─────────────────────────────────────────────────────────────
      # Part 4: Step-by-Step Attack Flow (Detailed POC)
      # ─────────────────────────────────────────────────────────────
      detailed_steps:
        - step: 1
          phase: "Reconnaissance"
          action: "Enumerate API endpoints via /swagger.json"
          technique: T1592.002
          tools: ["curl", "burpsuite"]
          commands: |
            curl -s https://target.com/swagger.json | jq '.paths | keys'
          expected_result: "List of all API endpoints"

        - step: 2
          phase: "Initial Access"
          action: "Access unprotected /api/v2/user endpoint"
          technique: T1190
          tools: ["curl"]
          commands: |
            curl -s https://target.com/api/v2/user/profile \
              -H "X-Forwarded-For: 127.0.0.1"
          expected_result: "User profile data returned without authentication"

        - step: 3
          phase: "Credential Access"
          action: "Extract session tokens from response"
          technique: T1552.001
          tools: ["jq", "python"]
          poc_code: |
            import requests
            resp = requests.get("https://target.com/api/v2/user/profile")
            tokens = resp.json().get("active_sessions", [])
            print(f"Extracted {len(tokens)} session tokens")
          expected_result: "Valid session tokens extracted"

        - step: 4
          phase: "Lateral Movement"
          action: "Use extracted tokens to access other user accounts"
          technique: T1550.001
          commands: |
            for token in $TOKENS; do
              curl -s https://target.com/api/v1/admin \
                -H "Authorization: Bearer $token"
            done
          expected_result: "Access to admin functionality"

  # ─────────────────────────────────────────────────────────────────
  # Part 5: Feasibility Assessment (可行性评估)
  # ─────────────────────────────────────────────────────────────────
  feasibility_assessment:
    - risk_id: "VR-001"
      attack_feasibility:
        access_required: "Network"          # Network/Adjacent/Local/Physical
        privileges_required: "None"         # None/Low/High
        user_interaction: "None"            # None/Required
        exploit_complexity: "Low"           # Low/High
      detection_likelihood: "Low"           # Low/Medium/High
      overall_feasibility: "High"           # Critical/High/Medium/Low
      feasibility_score: 9.5               # 0.0-10.0
```

---

## Attack Path Validation Standards (攻击路径验证标准)

有效攻击路径必须满足以下验证标准:

### 最小结构要求

| 要求 | 标准 | 说明 |
|------|------|------|
| **最小步骤数** | ≥ 2 | Entry Point + Impact (至少) |
| **最大步骤数** | ≤ 10 | 超过10步需拆分为多个路径 |
| **必须包含** | entry_point, target | 起点和终点 |
| **每步必填** | step, phase, action | 序号、阶段、动作 |

### 每步骤必填字段

```yaml
step_requirements:
  required:
    - step: integer          # 步骤序号 (1-N)
    - phase: string          # 攻击阶段 (Reconnaissance/Initial Access/...)
    - action: string         # 具体动作描述
  recommended:
    - technique: string      # ATT&CK 技术编号 (T1xxx)
    - tools: array[string]   # 使用的工具
    - commands: string       # 具体命令或代码
    - expected_result: string # 预期结果
```

### 有效路径判定规则

```yaml
valid_path_criteria:
  entry_point:
    must_be_one_of:
      - "External:*"              # 外部来源
      - "Compromised:*"           # 已被攻陷的组件
      - "Insider:*"               # 内部人员

  target:
    must_be_one_of:
      - "DataStore:*"             # 数据存储
      - "Process:*"               # 关键进程
      - "Service:*"               # 服务
      - "Impact:*"                # 影响描述

  chain_continuity:
    rule: "每步的结果必须能作为下一步的前提条件"
    validation: "检查 expected_result[N] 是否支持 action[N+1]"

  trust_boundary_crossing:
    rule: "至少跨越一个信任边界"
    exception: "内部威胁场景可豁免"
```

---

## POC Verification Methodology Template (POC验证方法论)

> **Critical Quality Requirement**: 专业渗透测试级别质量

### 验证方法论表

```markdown
## 验证方法论

| 验证级别 | 说明 | 示例场景 |
|---------|------|---------|
| ✅ **已验证** | 通过代码审计/静态分析确认可利用，已有POC代码 | 硬编码密钥、SQL注入代码路径 |
| ⚠️ **需验证** | 需要运行时环境/网络条件验证 | SSRF DNS Rebinding、时序攻击 |
| 📋 **理论可行** | 代码路径存在，需特定条件触发 | 竞争条件、内存损坏 |
```

### POC Code Example Template (独立POC代码块模板)

每个高危威胁必须包含独立的 POC 代码块，格式如下：

```markdown
#### POC-{SEQ:03d}: {POC_TITLE}

` ``python
# POC: {简述目的}
# 前提: {前置条件列表}

import requests
import jwt  # 按需导入

# ============================================
# Step 1: {步骤描述}
# ============================================
# {详细说明}

# ============================================
# Step 2: {步骤描述}
# ============================================
# {代码实现}

# ============================================
# Verification: {验证方法}
# ============================================
# 预期结果: {expected_result}
` ``

**验证状态**: ✅ 代码路径已确认 / ⚠️ 需运行时验证 / 📋 理论可行
**利用难度**: 低 (无需交互) / 中 (需要特定条件) / 高 (需复杂环境)
**影响**: {影响描述，如: 完全身份伪造、服务器完全控制}
```

**POC 代码质量要求**:
- 必须包含完整的 import 语句
- 必须有清晰的步骤注释
- 必须说明前置条件和预期结果
- 代码应可直接执行（修改目标地址后）

---

## Attack Path Feasibility Matrix Template (攻击路径可行性矩阵)

> **Critical Quality Requirement**: 量化攻击可行性，支持风险优先级排序

```markdown
## 攻击路径可行性矩阵

| 攻击路径 | 入口 | 所需权限 | 利用复杂度 | 检测难度 | 综合评分 |
|---------|------|---------|-----------|---------|---------|
| {路径描述} | {网络/内网/物理} | {无/用户/管理员} | {低/中/高} | {低/中/高} | **{0.0-10.0}** |

### 评分计算方法

综合评分 = 基础分 × 权限修正 × 复杂度修正 × 检测难度修正

| 因素 | 值 | 修正系数 |
|------|-----|---------|
| **基础分** | CVSS Base Score | 1.0 |
| **所需权限** | 无 | ×1.0 |
| | 用户 | ×0.9 |
| | 管理员 | ×0.7 |
| **利用复杂度** | 低 | ×1.0 |
| | 中 | ×0.85 |
| | 高 | ×0.7 |
| **检测难度** | 高 (难检测) | ×1.1 |
| | 中 | ×1.0 |
| | 低 (易检测) | ×0.9 |
```

---

## Attack Chain ASCII Art Box Template (攻击链ASCII图框模板)

每个主要攻击路径必须包含 ASCII 图框表示:

```markdown
## 攻击链分析

### 攻击链 {N}: {ATTACK_CHAIN_NAME}

` ``
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Attack Chain {N}: {ATTACK_CHAIN_NAME}                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. {Step 1 Title}                                                          │
│     {Step 1 描述}                                                            │
│     {代码片段或命令 (如有)}                                                   │
│                                  │                                           │
│                                  ▼                                           │
│  2. {Step 2 Title}                                                          │
│     {Step 2 描述}                                                            │
│     {关键代码路径: file.py:line}                                             │
│                                  │                                           │
│                                  ▼                                           │
│  3. {Step 3 Title}                                                          │
│     {Step 3 描述}                                                            │
│                                  │                                           │
│                                  ▼                                           │
│  4. {Impact Description}                                                     │
│     {最终影响和后果}                                                          │
│                                                                              │
│  CVSS: {X.X} ({Critical/High/Medium}) | 可利用性: {高/中/低} | 影响: {描述}  │
└─────────────────────────────────────────────────────────────────────────────┘
` ``
```

**攻击链图框要求**:
1. 每个攻击链必须使用标准边框 (┌─┐, │, └─┘)
2. 步骤之间使用箭头 (│, ▼) 连接
3. 底部必须包含 CVSS 评分、可利用性和影响摘要
4. 关键代码位置必须标注 (file.py:line)

---

## Verification Summary Template

```markdown
## 验证方式汇总

### 风险统计
| 分类 | Critical/High | Medium | Low | Total |
|------|---------------|--------|-----|-------|
| Spoofing | X | X | X | X |
| Tampering | X | X | X | X |
| Repudiation | X | X | X | X |
| Info Disclosure | X | X | X | X |
| Denial of Service | X | X | X | X |
| Elevation | X | X | X | X |
| **Total** | **XX** | **XX** | **XX** | **XX** |

### 详细验证结果
| 风险ID | 攻击路径 | CAPEC | ATT&CK | WSTG Tests | POC方法 | 验证状态 |
|--------|---------|-------|--------|------------|--------|---------|
| VR-001 | 绕过认证→数据访问 | CAPEC-151 | T1078 | WSTG-ATHN-04 | 直接访问 | 已验证 |
| VR-002 | SQL注入→数据泄露 | CAPEC-66 | T1190 | WSTG-INPV-05 | SQLMap | 已验证 |
| VR-003 | 权限提升→越权访问 | CAPEC-122 | T1087 | WSTG-AUTHZ-02 | ID遍历 | 已验证 |

### 攻击路径汇总
| 路径ID | 名称 | 涉及风险 | 复杂度 | 影响 |
|--------|------|---------|--------|------|
| AP-001 | 认证绕过到数据泄露 | VR-001, VR-005 | 中 | 严重 |
| AP-002 | 注入攻击链 | VR-002, VR-008 | 低 | 严重 |
```

---

## Checkpoint

Before proceeding to Phase 7, verify:
- [ ] All findings from P1-P5 consolidated and deduplicated
- [ ] Each threat has detailed risk analysis (Part 2)
- [ ] CAPEC and ATT&CK mappings complete
- [ ] Verification Set tests referenced (WSTG/MASTG)
- [ ] POC methods defined with step-by-step commands (Part 4)
- [ ] Attack paths constructed with chained risks (Part 3)
- [ ] Feasibility assessment completed (Part 5)
- [ ] KEV/CVE checked for exploitability context

**Reflection**: Review attack paths for realism. Prioritize threats with easier exploitation paths and verified POCs.

---

## Output File

**输出文件**: `.phase_working/P6-RISK-VALIDATION.md`

**文件头部**:
```markdown
---
phase: 6
name: "RISK-VALIDATION"
project: "{PROJECT}"
session_id: "{SESSION_ID}"
completed_at: "{ISO_TIMESTAMP}"
framework_version: "v2.0.3"
---

# Phase 6: 风险验证

[阶段内容...]
```

**→ Next**: Phase 7 (Mitigation Generation) - See `REPORT.md`
