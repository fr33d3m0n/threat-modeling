<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

# Risk Detail Schema

> **版本**: 2.0.0
> **最后更新**: 2026-01-02
> **所属模块**: Report Module v2.0.4

---

## 1. 概述

本文档定义威胁建模过程中风险详情的标准数据格式，确保所有风险信息的完整性和一致性。

**适用范围**:
- Phase 5 (STRIDE Analysis) 生成的威胁
- Phase 6 (Risk Validation) 验证的攻击路径
- Phase 7 (Mitigation) 生成的缓解措施
- Phase 8 (Report) 输出的风险详情块

---

## 2. 核心实体模型

### 2.0 实体关系概览

```
Finding (P1-P4)  →  Threat (P5)  →  ValidatedRisk (P6)  →  Mitigation (P7)
  F-P{N}-{Seq}     T-{S}-{E}-{Seq}     VR-{Seq}             M-{Seq}
                        │
                   threat_refs[] (MANDATORY)
```

**数量守恒公式**: `P5.total = consolidated_into_vr + excluded_with_reason`

### 2.1 威胁 (Threat) - Phase 5

**ID格式**: `T-{STRIDE}-{ElementID}-{Seq}`

| 字段 | 格式 | 示例 |
|------|------|------|
| STRIDE | S/T/R/I/D/E | S, T, R, I, D, E |
| ElementID | P{NN}/DS{NN}/DF{NN}/EI{NN} | P01, DS01, DF01, EI01 |
| Seq | NNN | 001, 002, 003 |

**示例**: `T-S-P01-001`, `T-T-DS01-002`, `T-I-DF03-001`

### 2.2 验证风险 (ValidatedRisk) - Phase 6

**ID格式**: `VR-{Seq}`

| 字段 | 格式 | 示例 |
|------|------|------|
| Seq | NNN | 001, 002, 003 |

**示例**: `VR-001`, `VR-015`

```yaml
ValidatedRisk:
  id: "VR-001"
  threat_refs: ["T-T-P13-001", "T-T-P13-002", "T-E-P13-001"]  # ⚠️ MANDATORY
  finding_refs: ["F-P4-003"]                                   # Optional
  severity: critical
  cvss_score: 10.0
  validation_status: verified
```

> ⚠️ **关键字段**: `threat_refs[]` 必填，追溯到 P5 原始威胁，用于数量守恒验证

**禁止的 ID 格式**:
- ❌ `RISK-001` → 使用 `VR-001`
- ❌ `T-E-RCE-001` → 使用 `T-E-P13-001` (保留 ElementID)

### 2.3 发现 (Finding) - Phase 1-4

**ID格式**: `F-P{N}-{Seq}`

| 字段 | 格式 | 示例 |
|------|------|------|
| Phase | P1/P2/P3/P4 | P1, P2, P3, P4 |
| Seq | NNN | 001, 002, 003 |

**示例**: `F-P1-001`, `F-P4-002`

### 2.4 缓解措施 (Mitigation) - Phase 7

**ID格式**: `M-{Seq}`

| 字段 | 格式 | 示例 |
|------|------|------|
| Seq | NNN | 001, 002, 003 |

**示例**: `M-001`, `M-005`

---

## 3. 风险详情标准格式

### 3.1 YAML Schema 定义

```yaml
# risk-detail.schema.yaml
# 威胁详情标准格式 - v1.0.0

risk_detail:
  # ============================================
  # 基本信息 (Basic Information)
  # ============================================
  id:
    type: string
    required: true
    format: "VR-{Seq}"
    description: "验证风险唯一标识符"
    example: "VR-001"

  # ============================================
  # 追溯引用 (Traceability References) - NEW v2.0
  # ============================================
  threat_refs:
    type: array[string]
    required: true    # ⚠️ MANDATORY
    format: "T-{STRIDE}-{ElementID}-{Seq}"
    description: "此风险来源的所有威胁 ID (来自 P5)"
    example: ["T-T-P13-001", "T-T-P13-002", "T-E-P13-001"]
    min_length: 1
    validation: "用于数量守恒验证: consolidated + excluded = P5.total"

  finding_refs:
    type: array[string]
    required: false
    format: "F-P{N}-{Seq}"
    description: "此风险来源的 P1-P4 发现 (可选)"
    example: ["F-P4-003"]

  name:
    type: string
    required: true
    max_length: 100
    description: "风险简短名称"
    example: "JWT Token 伪造"

  stride_category:
    type: enum
    required: true
    values: [S, T, R, I, D, E]
    mapping:
      S: "Spoofing (欺骗)"
      T: "Tampering (篡改)"
      R: "Repudiation (抵赖)"
      I: "Information Disclosure (信息泄露)"
      D: "Denial of Service (拒绝服务)"
      E: "Elevation of Privilege (权限提升)"

  element_id:
    type: string
    required: true
    format: "P{NN}|DS{NN}|DF{NN}|EI{NN}|TB{NN}"
    description: "受影响的 DFD 元素ID"
    example: "P01"

  element_name:
    type: string
    required: true
    description: "受影响元素的名称"
    example: "认证服务 (AuthService)"

  # ============================================
  # 描述信息 (Description)
  # ============================================
  description:
    brief:
      type: string
      required: true
      max_length: 200
      description: "一句话风险描述"
      example: "攻击者可伪造JWT令牌绕过身份认证"

    detailed:
      type: string
      required: true
      min_length: 100
      description: "详细技术描述，包括攻击原理和影响范围"
      example: |
        系统使用弱密钥(如默认密钥或短密钥)签署JWT令牌，
        攻击者可通过暴力破解或已知密钥列表猜测密钥，
        然后伪造有效的认证令牌访问系统资源。

  # ============================================
  # 位置信息 (Location)
  # ============================================
  location:
    component:
      type: string
      required: true
      description: "受影响组件名称"
      example: "packages/cli/src/auth"

    file:
      type: string
      required: true
      description: "文件路径"
      example: "packages/cli/src/auth/jwt.service.ts"

    line_range:
      type: string
      required: false
      format: "L{start}-L{end}"
      description: "代码行范围"
      example: "L45-L67"

    code_snippet:
      type: string
      required: false
      max_length: 500
      description: "相关代码片段(可选)"
      example: |
        const token = jwt.sign(payload, 'weak-secret-key', {
          expiresIn: '24h'
        });

  # ============================================
  # 原因分析 (Cause Analysis)
  # ============================================
  cause_analysis:
    root_cause:
      type: string
      required: true
      description: "根本原因分析"
      example: "使用硬编码的弱密钥进行JWT签名"

    contributing_factors:
      type: array[string]
      required: false
      description: "贡献因素列表"
      example:
        - "缺乏密钥轮换机制"
        - "未使用密钥管理服务"

    related_cwe:
      type: string
      required: true
      format: "CWE-{NNN}"
      description: "相关CWE编号"
      example: "CWE-347"
      kb_lookup: true

    related_capec:
      type: string
      required: false
      format: "CAPEC-{NNN}"
      description: "相关CAPEC编号"
      example: "CAPEC-233"
      kb_lookup: true

  # ============================================
  # 攻击信息 (Attack Information)
  # ============================================
  attack_info:
    attack_path:
      type: string
      required: true
      description: "攻击路径描述"
      format: "Entry → Step1 → Step2 → ... → Impact"
      example: "攻击者 → 获取有效JWT → 暴力破解密钥 → 伪造管理员Token → 访问管理API"

    prerequisites:
      type: array[string]
      required: false
      description: "攻击前置条件"
      example:
        - "能够获取一个有效的JWT令牌样本"
        - "拥有计算资源进行密钥暴力破解"

    attck_technique:
      type: string
      required: false
      format: "T{NNNN}"
      description: "MITRE ATT&CK 技术编号"
      example: "T1078"
      kb_lookup: true

    poc_method:
      type: object
      required: true
      properties:
        type:
          type: enum
          values: [manual, automated, command, script]
          description: "验证方法类型"
        description:
          type: string
          required: true
          description: "POC验证方法描述"
        command:
          type: string
          required: false
          description: "验证命令或脚本"
      example:
        type: "command"
        description: "使用 jwt-cracker 工具暴力破解弱密钥"
        command: "jwt-cracker <token> --max-length 10"

    exploitability:
      type: enum
      required: true
      values: [Very High, High, Medium, Low]
      description: "可利用性评估"
      scoring:
        Very High: "无需特殊条件即可利用"
        High: "需要少量前置条件"
        Medium: "需要特定条件或技术能力"
        Low: "需要复杂条件或高级技术"

  # ============================================
  # 影响评估 (Impact Assessment)
  # ============================================
  impact:
    confidentiality:
      type: enum
      required: true
      values: [High, Medium, Low, None]
      description: "机密性影响"

    integrity:
      type: enum
      required: true
      values: [High, Medium, Low, None]
      description: "完整性影响"

    availability:
      type: enum
      required: true
      values: [High, Medium, Low, None]
      description: "可用性影响"

    cvss_score:
      type: float
      required: true
      range: [0.0, 10.0]
      description: "CVSS 3.1 评分"
      example: 8.8

    cvss_vector:
      type: string
      required: false
      format: "CVSS:3.1/AV:.../AC:.../..."
      description: "CVSS 向量字符串"
      example: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"

  # ============================================
  # 缓解措施 (Mitigation)
  # ============================================
  mitigation:
    priority:
      type: enum
      required: true
      values: [P0, P1, P2, P3]
      mapping:
        P0: "立即修复 - Critical 风险"
        P1: "紧急 - High 风险"
        P2: "高优先级 - Medium 风险"
        P3: "计划中 - Low 风险"

    strategy:
      type: string
      required: true
      description: "缓解策略概述"
      example: "使用强密钥和密钥管理服务，实施密钥轮换"

    short_term:
      description:
        type: string
        required: true
        description: "短期修复方案描述"
      implementation:
        type: string
        required: false
        description: "代码或配置示例"

    long_term:
      description:
        type: string
        required: false
        description: "长期解决方案描述"
      implementation:
        type: string
        required: false
        description: "架构级改进方案"

    kb_reference:
      type: string
      required: false
      description: "知识库参考来源"
      example: "codeguard-authentication.yaml → jwt_weak_signing_key"
```

---

## 4. 严重程度映射

### 4.1 CVSS 到严重程度

| CVSS 评分 | 严重程度 | 图标 | 优先级 |
|-----------|---------|------|--------|
| 9.0 - 10.0 | Critical | 🔴 | P0 |
| 7.0 - 8.9 | High | 🟠 | P1 |
| 4.0 - 6.9 | Medium | 🟡 | P2 |
| 0.1 - 3.9 | Low | 🟢 | P3 |

### 4.2 STRIDE 到默认影响

| STRIDE | 主要影响 | 默认 CIA |
|--------|---------|----------|
| Spoofing (S) | 机密性、完整性 | C:H, I:M, A:N |
| Tampering (T) | 完整性 | C:L, I:H, A:M |
| Repudiation (R) | 不可否认性 | C:L, I:M, A:N |
| Info Disclosure (I) | 机密性 | C:H, I:N, A:N |
| DoS (D) | 可用性 | C:N, I:N, A:H |
| EoP (E) | 完整性、机密性 | C:H, I:H, A:M |

---

## 5. 字段完整性规则

### 5.1 必填字段清单

以下字段在所有风险详情中必须填写:

```yaml
required_fields:
  core:
    - id                          # 风险ID (VR-xxx)
    - threat_refs                 # ⚠️ 原始威胁引用 (MANDATORY v2.0)
    - name                        # 风险名称
    - stride_category             # STRIDE分类
    - element_id                  # 受影响元素
    - element_name                # 元素名称

  description:
    - description.brief           # 简述
    - description.detailed        # 详细描述

  location:
    - location.component          # 组件名称
    - location.file               # 文件位置

  cause:
    - cause_analysis.root_cause   # 根本原因
    - cause_analysis.related_cwe  # CWE映射

  attack:
    - attack_info.attack_path     # 攻击路径
    - attack_info.poc_method      # POC方法
    - attack_info.exploitability  # 可利用性

  impact:
    - impact.confidentiality      # 机密性影响
    - impact.integrity            # 完整性影响
    - impact.availability         # 可用性影响
    - impact.cvss_score           # CVSS评分

  mitigation:
    - mitigation.priority         # 优先级
    - mitigation.strategy         # 缓解策略
    - mitigation.short_term.description  # 短期修复
```

### 5.2 完整性验证规则

```yaml
validation_rules:
  - name: "ID格式验证"
    field: "id"
    rule: "matches('^T-[STRIDE]-[A-Z]+[0-9]+-[0-9]{3}$')"

  - name: "描述最小长度"
    field: "description.detailed"
    rule: "length >= 100"

  - name: "CWE格式验证"
    field: "cause_analysis.related_cwe"
    rule: "matches('^CWE-[0-9]+$')"

  - name: "CVSS范围验证"
    field: "impact.cvss_score"
    rule: "value >= 0.0 AND value <= 10.0"

  - name: "攻击路径格式"
    field: "attack_info.attack_path"
    rule: "contains('→')"

completeness_threshold: 95%
```

---

## 6. Markdown 输出模板

以下是风险详情在报告中的标准 Markdown 格式:

```markdown
### {id}: {name}

**基本信息**:
| 属性 | 值 |
|------|-----|
| 风险ID | {id} |
| **Threat Refs** | {threat_refs} |
| STRIDE类型 | {stride_category_full} |
| 受影响元素 | {element_id} - {element_name} |
| 严重程度 | {severity_icon} {severity} |
| CVSS评分 | {cvss_score} |

**风险描述**:
{description.brief}

**详细说明**:
{description.detailed}

**位置定位**:
- **组件**: {location.component}
- **文件**: `{location.file}:{location.line_range}`
- **关键代码**:
  ```{language}
  {location.code_snippet}
  ```

**原因分析**:
- **根本原因**: {cause_analysis.root_cause}
- **相关CWE**: {cause_analysis.related_cwe} ({cwe_name})
- **相关CAPEC**: {cause_analysis.related_capec} ({capec_name})

**攻击路径**:
```
{attack_info.attack_path}
```

**前置条件**:
{attack_info.prerequisites - as numbered list}

**ATT&CK映射**: {attack_info.attck_technique} - {attck_name}

**POC验证方法**:
```{poc_language}
{attack_info.poc_method.command}
```

**影响评估**:
| 维度 | 影响程度 |
|------|---------|
| 机密性 | {impact.confidentiality} |
| 完整性 | {impact.integrity} |
| 可用性 | {impact.availability} |

**缓解措施**:

**优先级**: {mitigation.priority} - {priority_description}

**短期修复**:
{mitigation.short_term.description}
```{language}
{mitigation.short_term.implementation}
```

**长期方案**:
{mitigation.long_term.description}

**KB参考**: {mitigation.kb_reference}

---
```

---

## 7. 与其他 Schema 的关系

```
┌─────────────────────────────────────────────────────────────────┐
│                     Schema Dependencies                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  risk-detail.schema.md (本文档)                                  │
│         │                                                        │
│         ├─── 被引用于: phase-risk-summary.schema.md              │
│         │    (阶段风险汇总格式)                                   │
│         │                                                        │
│         ├─── 被引用于: assets/templates/RISK-INVENTORY.template.md      │
│         │    (风险清单报告模板)                                   │
│         │                                                        │
│         └─── 被引用于: assets/templates/THREAT-MODEL-REPORT.template.md │
│              (主报告威胁详情章节)                                 │
│                                                                  │
│  依赖关系:                                                       │
│  - report-naming.schema.md (报告命名规范)                        │
│  - knowledge/codeguard-*.yaml (KB查询源)                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. 版本历史

| 版本 | 日期 | 变更说明 |
|------|------|---------|
| 1.0.0 | 2025-12-26 | 初始版本，定义威胁详情标准格式 |
| 2.0.0 | 2026-01-02 | **数据架构重构**: 添加 ValidatedRisk 实体，`threat_refs[]` 必填字段，数量守恒公式 |

---

**文档结束**
