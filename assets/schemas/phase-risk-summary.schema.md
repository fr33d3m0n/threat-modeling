<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

# Phase Risk Summary Schema

> **版本**: 2.0.0
> **最后更新**: 2026-01-02
> **所属模块**: Report Module v2.0.4

---

## 1. 概述

本文档定义威胁建模各阶段结束时风险汇总的标准格式，确保跨阶段的风险信息完整传递。

**设计原则**:
- 每个阶段结束时必须输出风险汇总
- Phase 1-4 产生发现 (Finding: F-P{N}-{Seq})
- Phase 5 产生威胁 (Threat: T-{STRIDE}-{Element}-{Seq})
- Phase 6 产生验证风险 (ValidatedRisk: VR-{Seq})
- Phase 7 产生缓解措施 (Mitigation: M-{Seq})
- **必须保证数量守恒**: `P5.total = consolidated_into_vr + excluded_with_reason`

**核心实体模型 (v2.0)**:
```
Finding (P1-P4)  →  Threat (P5)  →  ValidatedRisk (P6)  →  Mitigation (P7)
  F-P{N}-{Seq}     T-{S}-{E}-{Seq}     VR-{Seq}             M-{Seq}
                        │
                   threat_refs[] (MANDATORY)
```

---

## 2. 阶段输出结构

### 2.1 Phase Context Protocol 扩展

```yaml
# 现有 Phase Context 结构
phase_output:
  phase_id: "P{N}"
  phase_name: "阶段名称"
  status: "completed"
  timestamp: "YYYY-MM-DD HH:MM:SS"

  # === 新增: 风险汇总字段 ===
  risk_summary:
    total_count: N
    by_severity:
      critical: N
      high: N
      medium: N
      low: N
    items: []  # 风险列表

  phase_reflection:
    key_findings: []
    attention_areas: []
    handover_notes: []
```

---

## 3. Phase 1-4: 安全发现格式

### 3.1 Security Finding Schema

```yaml
# security-finding.schema.yaml
security_finding:
  id:
    type: string
    required: true
    format: "SF-P{N}-{Seq}"
    example: "SF-P1-001"

  phase:
    type: integer
    required: true
    range: [1, 4]
    description: "发现来源阶段"

  type:
    type: enum
    required: true
    values:
      - missing_security_control    # 缺失安全控制
      - weak_configuration          # 弱配置
      - design_flaw                 # 设计缺陷
      - hardcoded_secret            # 硬编码敏感信息
      - insufficient_validation     # 验证不足
      - missing_encryption          # 缺失加密
      - insecure_dependency         # 不安全依赖
      - other                       # 其他

  title:
    type: string
    required: true
    max_length: 100
    description: "发现标题"

  description:
    type: string
    required: true
    description: "发现描述"

  location:
    component:
      type: string
      required: true
    file:
      type: string
      required: false
    line:
      type: string
      required: false

  severity:
    type: enum
    required: true
    values: [Critical, High, Medium, Low, Info]

  risk_indicator:
    type: string
    required: false
    description: "风险指示器，供后续阶段深入分析"

  recommended_action:
    type: enum
    required: true
    values:
      - deep_analysis_p5    # P5 深入分析
      - deep_analysis_p6    # P6 验证
      - immediate_fix       # 立即修复
      - monitor             # 监控
      - accept              # 接受
```

### 3.2 Phase 1-4 风险汇总模板

```markdown
## 阶段安全发现汇总

### P{N} 发现统计
| 严重程度 | 数量 | 百分比 |
|---------|------|--------|
| Critical | X | X% |
| High | X | X% |
| Medium | X | X% |
| Low | X | X% |
| Info | X | X% |
| **总计** | **X** | **100%** |

### 本阶段发现清单

| 发现ID | 类型 | 标题 | 位置 | 严重程度 | 后续阶段 |
|--------|------|------|------|---------|---------|
| SF-P{N}-001 | [类型] | [标题] | `[文件:行]` | 🔴/🟠/🟡/🟢 Critical/High/Medium/Low | P5/P6 |
| SF-P{N}-002 | [类型] | [标题] | `[文件:行]` | 🟠 High | P5 |

### 风险指示器 (供后续分析)

| 指示器描述 | 相关发现 | 建议分析深度 |
|-----------|---------|-------------|
| [指示器1] | SF-P{N}-001 | Deep |
| [指示器2] | SF-P{N}-002, SF-P{N}-003 | Standard |

### 阶段反思

**关键发现**:
1. [关键发现1]
2. [关键发现2]

**需要关注**:
1. [关注点1]
2. [关注点2]

**传递给下阶段**:
1. [传递信息1]
2. [传递信息2]

---
```

---

## 4. Phase 5-7: 威胁格式

### 4.1 Threat Summary Schema

```yaml
# threat-summary.schema.yaml
threat_summary:
  id:
    type: string
    required: true
    format: "T-{STRIDE}-{ElementID}-{Seq}"
    example: "T-S-P01-001"

  stride_category:
    type: enum
    required: true
    values: [S, T, R, I, D, E]

  element_id:
    type: string
    required: true

  element_name:
    type: string
    required: true

  title:
    type: string
    required: true
    max_length: 100

  description_brief:
    type: string
    required: true
    max_length: 200

  cwe:
    type: string
    required: true
    format: "CWE-{NNN}"

  cvss_score:
    type: float
    required: true
    range: [0.0, 10.0]

  severity:
    type: enum
    required: true
    values: [Critical, High, Medium, Low]

  status:
    type: enum
    required: true
    values:
      - identified        # P5: 已识别
      - validated         # P6: 已验证
      - mitigated         # P7: 已有缓解方案
      - accepted          # 接受风险
      - false_positive    # 误报

  validation_result:
    type: object
    required: false  # P6 填充
    properties:
      attack_path_confirmed: boolean
      poc_available: boolean
      exploitability: enum[Very High, High, Medium, Low]

  mitigation_status:
    type: object
    required: false  # P7 填充
    properties:
      priority: enum[P0, P1, P2, P3]
      strategy_defined: boolean
      short_term_available: boolean
      long_term_available: boolean
```

### 4.2 Phase 5-7 威胁汇总模板

```markdown
## 阶段威胁汇总

### P{N} 威胁统计

#### 按严重程度
| 严重程度 | 数量 | 百分比 |
|---------|------|--------|
| 🔴 Critical | X | X% |
| 🟠 High | X | X% |
| 🟡 Medium | X | X% |
| 🟢 Low | X | X% |
| **总计** | **X** | **100%** |

#### 按 STRIDE 类别
| STRIDE | 名称 | 数量 | Critical | High | Medium | Low |
|--------|------|------|----------|------|--------|-----|
| S | Spoofing | X | X | X | X | X |
| T | Tampering | X | X | X | X | X |
| R | Repudiation | X | X | X | X | X |
| I | Info Disclosure | X | X | X | X | X |
| D | DoS | X | X | X | X | X |
| E | EoP | X | X | X | X | X |

### 本阶段威胁清单

| 威胁ID | STRIDE | 元素 | 标题 | CWE | CVSS | 严重程度 | 状态 |
|--------|--------|------|------|-----|------|---------|------|
| T-S-P01-001 | S | P01 | [标题] | CWE-XXX | X.X | 🔴 Critical | [状态] |
| T-T-DS01-001 | T | DS01 | [标题] | CWE-XXX | X.X | 🟠 High | [状态] |

### 高风险元素分布

| 元素ID | 元素名称 | 威胁数 | 最高严重程度 |
|--------|---------|--------|-------------|
| P01 | [名称] | X | 🔴 Critical |
| DS01 | [名称] | X | 🟠 High |

### 阶段反思

**关键威胁**:
1. [关键威胁1] - 原因分析
2. [关键威胁2] - 原因分析

**高风险区域**:
1. [区域1]: X 个威胁
2. [区域2]: X 个威胁

**传递给下阶段**:
1. [需要 P{N+1} 处理的事项]
2. [需要 P{N+1} 处理的事项]

---
```

---

## 5. 阶段特定字段

### 5.1 各阶段输出扩展

```yaml
# Phase 1: 项目理解
phase_1_extension:
  project_type: string            # Web/API/微服务/AI/LLM
  technology_stack: []            # 技术栈列表
  security_relevant_modules: []   # 安全相关模块
  initial_attack_surface: string  # 初始攻击面评估

# Phase 2: DFD 构建
phase_2_extension:
  dfd_elements:
    processes: []      # P01, P02, ...
    data_stores: []    # DS01, DS02, ...
    data_flows: []     # DF01, DF02, ...
    external_entities: []  # EI01, EI02, ...
  data_classification:
    pii: []            # 包含PII的元素
    credentials: []    # 包含凭证的元素
    sensitive: []      # 其他敏感数据

# Phase 3: 信任边界
phase_3_extension:
  trust_boundaries:
    - id: "TB01"
      name: "边界名称"
      type: "network|process|user|cloud"
      elements_inside: []
      crossing_flows: []
  critical_interfaces: []  # 关键接口列表

# Phase 4: 安全设计评估
phase_4_extension:
  security_domains:
    authentication:
      status: "implemented|partial|missing"
      gaps: []
    authorization:
      status: "implemented|partial|missing"
      gaps: []
    # ... 其他 9 个安全域
  design_matrix: {}  # 安全设计矩阵

# Phase 5: STRIDE 分析
phase_5_extension:
  stride_matrix: {}           # STRIDE per Interaction 矩阵
  threat_generation_filters: []  # 应用的过滤器
  kb_queries: []              # 知识库查询记录

# Phase 6: 风险验证 (v2.0 Updated)
phase_6_extension:
  # 验证风险列表 (新格式)
  validated_risks:
    - id: "VR-001"
      threat_refs: ["T-T-P13-001", "T-T-P13-002"]  # ⚠️ MANDATORY
      finding_refs: ["F-P4-003"]                    # Optional
      severity: critical
      cvss_score: 10.0
      validation_status: verified

  # 威胁处理记录 (数量守恒追溯)
  threat_disposition:
    input_count: 120  # P5 威胁总数
    output_summary:
      consolidated_into_vr: 98   # 合并到 VR
      excluded_with_reason: 22   # 排除 (有理由)
      validation_formula: "98 + 22 = 120 ✅"
    vr_threat_mapping:
      VR-001: ["T-T-P13-001", "T-T-P13-002", "T-E-P13-001"]
    excluded_threats:
      - threat_id: "T-S-P02-002"
        reason: "MITIGATED - escape_filter_chars() applied"

  attack_paths_confirmed: []  # 确认的攻击路径
  poc_methods: []             # POC 方法

# Phase 7: 缓解措施
phase_7_extension:
  mitigation_plan:
    p0_items: []    # 立即修复
    p1_items: []    # 紧急
    p2_items: []    # 高优先级
    p3_items: []    # 计划中
  defense_in_depth: {}  # 纵深防御架构
  compliance_mapping: {}  # 合规映射
```

---

## 6. 累积风险清单

### 6.1 Full Risk Registry Schema

```yaml
# 跨阶段累积的完整风险清单
full_risk_registry:
  metadata:
    project_name: string
    created_at: datetime
    last_updated: datetime
    total_risks: integer

  # Phase 1-4 安全发现
  security_findings:
    - id: "SF-P{N}-XXX"
      phase: N
      # ... security_finding schema fields
      status: "open|addressed|deferred"

  # Phase 5-7 威胁
  threats:
    - id: "T-X-XX-XXX"
      # ... threat_summary schema fields
      full_detail: {}  # 完整风险详情 (risk-detail.schema.md)

  # 汇总统计
  summary:
    by_phase:
      P1: { total: N, critical: N, high: N, medium: N, low: N }
      P2: { total: N, critical: N, high: N, medium: N, low: N }
      # ...
    by_severity:
      Critical: N
      High: N
      Medium: N
      Low: N
    by_stride:
      S: N
      T: N
      R: N
      I: N
      D: N
      E: N
    by_element:
      P01: N
      DS01: N
      # ...
```

---

## 7. Phase 8 上下文聚合

### 7.1 Aggregated Context Schema

```yaml
# P8 聚合上下文结构
aggregated_context:
  # P1-P7 阶段输出
  phase_outputs:
    P1: { project_context, security_findings }
    P2: { dfd_elements, security_findings }
    P3: { boundary_context, security_findings }
    P4: { security_gaps, security_findings }
    P5: { threat_inventory, stride_matrix }
    P6: { validated_threats, attack_paths }
    P7: { mitigation_plan, compliance_mapping }

  # 完整风险清单
  full_risk_registry: {}  # 见上文

  # 报告生成所需的统计信息
  report_statistics:
    total_threats: N
    critical_count: N
    high_count: N
    medium_count: N
    low_count: N
    mitigated_count: N
    pending_count: N

  # 质量指标
  quality_metrics:
    completeness_score: float  # 字段完整性
    coverage_score: float      # 元素覆盖率
    validation_score: float    # 验证完成率
```

---

## 8. 与其他 Schema 的关系

```
┌─────────────────────────────────────────────────────────────────┐
│                     Schema Dependencies                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  phase-risk-summary.schema.md (本文档)                           │
│         │                                                        │
│         ├─── 依赖: risk-detail.schema.md                         │
│         │    (威胁详情完整格式)                                   │
│         │                                                        │
│         ├─── 被引用于: WORKFLOW.md → Phase 1-7 章节              │
│         │    (各阶段风险汇总要求)                                 │
│         │                                                        │
│         └─── 被引用于: WORKFLOW.md → Phase 8 Step 8.1            │
│              (上下文聚合步骤)                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. 版本历史

| 版本 | 日期 | 变更说明 |
|------|------|---------|
| 1.0.0 | 2025-12-26 | 初始版本，定义阶段风险汇总格式 |
| 2.0.0 | 2026-01-02 | **数据架构重构**: 添加 ValidatedRisk 实体，`threat_refs[]` 必填，`threat_disposition` 追溯表 |

---

**文档结束**
