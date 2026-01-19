# Report Module Redesign - v1.0.2 设计文档

> **版本**: v1.0.2
> **日期**: 2025-12-26
> **状态**: 待评审
> **作者**: Claude (Design Phase)

---

## 1. 设计目标

基于用户 4 项要求重新设计报告生成模块:

| 要求 | 描述 | 设计响应 |
|------|------|---------|
| **要求1** | 确保风险信息记录充分 | 阶段风险汇总机制 + 风险详情标准格式 |
| **要求2** | 重新设计报告阶段工作流 | P8 新工作流: 聚合→分析→验证→输出→组装 |
| **要求3** | 标准化报告命名 | 8种标准报告定义 |
| **要求4** | 分离模块/流程/模板设计 | 三层架构设计 |

---

## 2. 架构设计

### 2.1 三层分离架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Report Generation Architecture                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │                     Layer 1: WORKFLOW (流程层)                         │   │
│  │                                                                        │   │
│  │  定义: P8 报告生成的执行流程和阶段                                      │   │
│  │  位置: WORKFLOW.md → Phase 8 章节                                      │   │
│  │  内容: 执行步骤、输入/输出规范、质量门禁                                 │   │
│  │                                                                        │   │
│  │  Phase 8 Workflow:                                                     │   │
│  │  8.1 Context Aggregation (上下文聚合)                                  │   │
│  │  8.2 Risk Deep Analysis (风险深度分析) - 可并行                         │   │
│  │  8.3 Gap Verification (差距验证)                                       │   │
│  │  8.4 Report Section Generation (章节生成)                              │   │
│  │  8.5 Report Assembly (报告组装)                                        │   │
│  │  8.6 Quality Validation (质量验证)                                     │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                    │                                          │
│                                    ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │                     Layer 2: TEMPLATES (模板层)                        │   │
│  │                                                                        │   │
│  │  定义: 各类报告的结构定义和字段规范                                     │   │
│  │  位置: assets/templates/ 目录                                                 │   │
│  │  内容: 报告结构、章节定义、风险详情字段                                  │   │
│  │                                                                        │   │
│  │  Templates:                                                            │   │
│  │  ├── THREAT-MODEL-REPORT.template.md                                   │   │
│  │  ├── ARCHITECTURE-ANALYSIS.template.md                                 │   │
│  │  ├── DFD-DIAGRAM.template.md                                           │   │
│  │  ├── RISK-INVENTORY.template.md                                        │   │
│  │  ├── MITIGATION-MEASURES.template.md                                   │   │
│  │  ├── COMPLIANCE-REPORT.template.md                                     │   │
│  │  ├── ATTACK-PATH-VALIDATION.template.md                                │   │
│  │  └── PENETRATION-TEST-PLAN.template.md                                 │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                    │                                          │
│                                    ▼                                          │
│  ┌───────────────────────────────────────────────────────────────────────┐   │
│  │                     Layer 3: SCHEMAS (规范层)                          │   │
│  │                                                                        │   │
│  │  定义: 数据结构、字段规范、命名约定                                     │   │
│  │  位置: assets/schemas/ 目录                                                   │   │
│  │  内容: 风险详情格式、阶段输出格式、命名规范                              │   │
│  │                                                                        │   │
│  │  Schemas:                                                              │   │
│  │  ├── risk-detail.schema.md          # 风险详情标准格式                  │   │
│  │  ├── phase-risk-summary.schema.md   # 阶段风险汇总格式                  │   │
│  │  └── report-naming.schema.md        # 报告命名规范                     │   │
│  └───────────────────────────────────────────────────────────────────────┘   │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. 阶段风险汇总机制 (要求1)

### 3.1 Phase Risk Summary Protocol

**每阶段结束时的风险汇总要求**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Phase Risk Summary Protocol                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  Phase 1-4: 安全发现 (Security Findings)                                      │
│  ─────────────────────────────────────────────────────────────────────────   │
│  类型: SF (Security Finding)                                                 │
│  格式: SF-P{N}-{Seq}                                                         │
│  示例: SF-P1-001, SF-P3-002                                                  │
│                                                                               │
│  阶段输出增加字段:                                                            │
│  - security_findings[]: 本阶段发现的安全问题                                  │
│  - risk_indicators[]: 风险指示器(供后续阶段深入分析)                          │
│                                                                               │
│  Phase 5-7: 威胁 (Threats)                                                    │
│  ─────────────────────────────────────────────────────────────────────────   │
│  类型: T (Threat)                                                            │
│  格式: T-{STRIDE}-{ElementID}-{Seq}                                          │
│  示例: T-S-P01-001, T-T-DS01-002                                             │
│                                                                               │
│  阶段输出字段:                                                                │
│  - threat_inventory[]: 威胁清单                                              │
│  - validated_threats[]: 已验证威胁(P6)                                       │
│  - mitigation_plan[]: 缓解计划(P7)                                           │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 阶段输出风险汇总格式

**Phase 1-4 安全发现汇总格式**:

```markdown
## 阶段安全发现汇总

### 本阶段发现
| 发现ID | 类型 | 描述 | 位置 | 风险等级 | 后续阶段 |
|--------|------|------|------|---------|---------|
| SF-P{N}-001 | [类型] | [简述] | `file:line` | High/Medium/Low | P5/P6 |

### 风险指示器 (供后续分析)
| 指示器 | 相关发现 | 建议分析深度 |
|--------|---------|-------------|
| [指示器描述] | SF-P{N}-XXX | Deep/Standard |

### 阶段反思
- 关键发现: [...]
- 需要关注: [...]
- 传递给下阶段: [...]
```

**Phase 5-7 威胁汇总格式**:

```markdown
## 阶段威胁汇总

### 本阶段威胁
| 威胁ID | STRIDE | 元素 | 描述 | CWE | 优先级 |
|--------|--------|------|------|-----|--------|
| T-X-XX-XXX | [S/T/R/I/D/E] | [ElementID] | [简述] | CWE-XXX | Critical/High/Medium/Low |

### 威胁统计
| 优先级 | 数量 | 百分比 |
|--------|------|--------|
| Critical | X | X% |
| High | X | X% |
| Medium | X | X% |
| Low | X | X% |

### 阶段反思
- 关键威胁: [...]
- 高风险区域: [...]
- 传递给下阶段: [...]
```

---

## 4. 风险详情标准格式 (要求1)

### 4.1 Risk Detail Schema

**每个风险的标准输出字段**:

```yaml
# risk-detail.schema.yaml
risk_detail:
  # 基本信息
  id: "T-{STRIDE}-{ElementID}-{Seq}"
  name: "风险名称"
  stride_category: "S|T|R|I|D|E"
  element_id: "P01|DS01|DF01|..."

  # 描述信息
  description:
    brief: "一句话风险描述"
    detailed: "详细技术描述，包括攻击原理"

  # 位置与原因
  location:
    component: "受影响组件名称"
    file: "path/to/file.ext"
    line_range: "L100-L150"
    code_snippet: "相关代码片段 (可选)"

  cause_analysis:
    root_cause: "根本原因分析"
    contributing_factors: ["因素1", "因素2"]
    related_cwe: "CWE-XXX"
    related_capec: "CAPEC-XXX"

  # 攻击信息
  attack_info:
    attack_path: "Entry → Step1 → Step2 → Impact"
    prerequisites: ["前置条件1", "前置条件2"]
    attck_technique: "TXXX"
    poc_method:
      type: "manual|automated|command"
      description: "POC验证方法描述"
      command: "可选的验证命令"
    exploitability: "Very High|High|Medium|Low"

  # 影响评估
  impact:
    confidentiality: "High|Medium|Low|None"
    integrity: "High|Medium|Low|None"
    availability: "High|Medium|Low|None"
    cvss_score: "X.X"
    cvss_vector: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"

  # 缓解措施
  mitigation:
    priority: "P0|P1|P2|P3"
    strategy: "缓解策略概述"
    short_term:
      description: "短期修复方案"
      implementation: "代码或配置示例"
    long_term:
      description: "长期解决方案"
      implementation: "架构级改进方案"
    kb_reference: "KB参考来源"
```

### 4.2 风险详情 Markdown 输出模板

```markdown
### T-{STRIDE}-{ElementID}-{Seq}: {风险名称}

**基本信息**:
| 属性 | 值 |
|------|-----|
| 威胁ID | T-X-XX-XXX |
| STRIDE类型 | [Spoofing/Tampering/...] |
| 受影响元素 | [ElementID] - [元素名称] |
| 严重程度 | 🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low |
| CVSS评分 | X.X |

**风险描述**:
[一句话简述]

**详细说明**:
[详细技术描述，包括攻击原理和影响范围]

**位置定位**:
- **组件**: [组件名称]
- **文件**: `path/to/file.ext:L100-L150`
- **关键代码**:
  ```language
  // 存在问题的代码片段
  vulnerable_code_here();
  ```

**原因分析**:
- **根本原因**: [根本原因描述]
- **相关CWE**: CWE-XXX ([CWE名称])
- **相关CAPEC**: CAPEC-XXX ([CAPEC名称])

**攻击路径**:
```
攻击者 → [入口点] → [步骤1] → [步骤2] → [最终影响]
```

**前置条件**:
1. [条件1]
2. [条件2]

**ATT&CK映射**: TXXX - [技术名称]

**POC验证方法**:
```bash
# 验证命令或步骤
verification_command_here
```

**影响评估**:
| 维度 | 影响程度 |
|------|---------|
| 机密性 | High/Medium/Low/None |
| 完整性 | High/Medium/Low/None |
| 可用性 | High/Medium/Low/None |

**缓解措施**:

**优先级**: P0 - 立即修复 / P1 - 7天内 / P2 - 30天内 / P3 - 规划中

**短期修复** (P0/P1):
[临时缓解方案描述]
```language
// 修复代码示例
secure_code_here();
```

**长期方案** (P2/P3):
[根本解决方案描述]

**KB参考**: [知识库查询来源]

---
```

---

## 5. P8 报告生成工作流 (要求2)

### 5.1 新工作流设计

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Phase 8: Report Generation Workflow                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  Step 8.1: Context Aggregation (上下文聚合)                                   │
│  ─────────────────────────────────────────────────────────────────────────   │
│  Input: P1-P7 所有阶段输出                                                    │
│  Action:                                                                      │
│    1. 收集所有阶段的 security_findings[] 和 threat_inventory[]               │
│    2. 构建完整风险清单 (Full Risk Registry)                                   │
│    3. 理解各阶段目标、输出和关键发现                                          │
│  Output: aggregated_context {                                                │
│    project_context, dfd_elements, boundary_context,                          │
│    security_gaps, full_risk_registry, mitigation_plan                        │
│  }                                                                            │
│                                                                               │
│                              ↓                                                │
│                                                                               │
│  Step 8.2: Risk Deep Analysis (风险深度分析) - 可并行                         │
│  ─────────────────────────────────────────────────────────────────────────   │
│  Input: full_risk_registry                                                    │
│  Action: 对每个风险进行标准化深度分析                                         │
│    ┌──────────────────────────────────────────────────────────────────────┐  │
│    │  Sub-Agent Pattern (Parallel)                                        │  │
│    │                                                                       │  │
│    │  Risk 1 ──► Agent ──► Deep Analysis ──► Standardized Detail         │  │
│    │  Risk 2 ──► Agent ──► Deep Analysis ──► Standardized Detail         │  │
│    │  ...                                                                  │  │
│    │  Risk N ──► Agent ──► Deep Analysis ──► Standardized Detail         │  │
│    └──────────────────────────────────────────────────────────────────────┘  │
│  Output: analyzed_risks[] (按标准格式)                                        │
│                                                                               │
│                              ↓                                                │
│                                                                               │
│  Step 8.3: Gap Verification (差距验证) - 条件执行                             │
│  ─────────────────────────────────────────────────────────────────────────   │
│  Condition: 当 analyzed_risks 中存在信息不完整项                              │
│  Action:                                                                      │
│    1. 识别缺失字段 (位置、POC、缓解措施等)                                    │
│    2. 返回代码库进行补充分析                                                  │
│    3. 查询KB补充缓解措施                                                      │
│  Output: verified_risks[] (完整的风险详情)                                    │
│                                                                               │
│                              ↓                                                │
│                                                                               │
│  Step 8.4: Report Section Generation (章节生成)                               │
│  ─────────────────────────────────────────────────────────────────────────   │
│  Input: verified_risks[], aggregated_context                                  │
│  Action: 按模板生成各报告章节                                                 │
│    1. Executive Summary                                                       │
│    2. Architecture Overview (from P1/P2)                                      │
│    3. Security Design Assessment (from P4)                                    │
│    4. STRIDE Threat Analysis (所有风险详情块)                                 │
│    5. Attack Surface Analysis                                                 │
│    6. Mitigation Recommendations (from P7)                                    │
│    7. Compliance Mapping                                                      │
│    8. Appendices                                                              │
│  Output: report_sections{}                                                    │
│                                                                               │
│                              ↓                                                │
│                                                                               │
│  Step 8.5: Report Assembly (报告组装)                                         │
│  ─────────────────────────────────────────────────────────────────────────   │
│  Input: report_sections{}                                                     │
│  Action: 按模板组装各类报告                                                   │
│    1. {PROJECT}-THREAT-MODEL-REPORT.md (主报告)                               │
│    2. {PROJECT}-ARCHITECTURE-ANALYSIS.md                                      │
│    3. {PROJECT}-DFD-DIAGRAM.md                                                │
│    4. {PROJECT}-RISK-INVENTORY.md                                             │
│    5. {PROJECT}-MITIGATION-MEASURES.md                                        │
│    6. {PROJECT}-COMPLIANCE-REPORT.md                                          │
│    7. {PROJECT}-ATTACK-PATH-VALIDATION.md                                     │
│    8. {PROJECT}-PENETRATION-TEST-PLAN.md                                      │
│  Output: 8份标准化报告文件                                                    │
│                                                                               │
│                              ↓                                                │
│                                                                               │
│  Step 8.6: Quality Validation (质量验证)                                      │
│  ─────────────────────────────────────────────────────────────────────────   │
│  Checklist:                                                                   │
│    [ ] 所有风险都有完整的5要素 (描述、位置、原因、攻击、缓解)                 │
│    [ ] 风险清单与详情块一一对应                                               │
│    [ ] 统计数据准确                                                           │
│    [ ] 报告格式符合模板                                                       │
│    [ ] 所有图表正确渲染                                                       │
│  Output: validated_reports (最终报告集)                                       │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 工作流详细步骤

#### Step 8.1: Context Aggregation

```markdown
## 8.1 上下文聚合

**目标**: 收集并理解 P1-P7 所有阶段的输出，构建完整风险清单。

**输入**:
- P1: project_context
- P2: dfd_elements
- P3: boundary_context
- P4: security_gaps
- P5: threat_inventory
- P6: validated_threats
- P7: mitigation_plan

**执行动作**:

1. **收集阶段风险**:
   - 从 P1-P4 收集 security_findings[]
   - 从 P5-P7 收集 threat_inventory[]
   - 合并为 full_risk_registry

2. **理解阶段目标和输出**:
   | 阶段 | 目标 | 关键输出 |
   |------|------|---------|
   | P1 | 项目理解 | 项目类型、模块、技术栈 |
   | P2 | DFD构建 | 元素清单、数据流图 |
   | P3 | 边界分析 | 信任边界、关键接口 |
   | P4 | 安全设计 | 安全差距、设计矩阵 |
   | P5 | STRIDE分析 | 威胁清单 (T-X-XX-XXX) |
   | P6 | 风险验证 | 攻击路径、POC方法 |
   | P7 | 缓解措施 | 修复方案、路线图 |

3. **构建完整风险清单**:
   将所有风险按优先级排序，标记来源阶段。

**输出**: aggregated_context
```

#### Step 8.2: Risk Deep Analysis

```markdown
## 8.2 风险深度分析

**目标**: 对每个风险进行标准化分析，确保所有字段完整。

**输入**: full_risk_registry

**执行模式**: 并行子代理

**每个风险的分析任务**:

1. **验证基本信息**:
   - 威胁ID是否符合格式
   - STRIDE分类是否正确
   - 元素ID是否有效

2. **补充详细描述**:
   - 简述 (1句话)
   - 详细说明 (技术细节)

3. **确认位置信息**:
   - 组件名称
   - 文件路径
   - 代码片段 (如适用)

4. **完善原因分析**:
   - 根本原因
   - CWE映射
   - CAPEC映射

5. **完善攻击信息**:
   - 攻击路径
   - 前置条件
   - ATT&CK映射
   - POC方法

6. **确认影响评估**:
   - CIA影响
   - CVSS评分

7. **确认缓解措施**:
   - 优先级
   - 短期修复
   - 长期方案

**输出**: analyzed_risks[] (标准格式)
```

#### Step 8.3: Gap Verification

```markdown
## 8.3 差距验证

**目标**: 补充任何缺失的风险信息。

**触发条件**: analyzed_risks 中存在信息不完整的风险

**缺失字段检查清单**:
| 字段 | 必需 | 验证方法 |
|------|------|---------|
| description.detailed | 是 | 长度 > 50 字符 |
| location.file | 是 | 非空 |
| cause_analysis.root_cause | 是 | 非空 |
| cause_analysis.related_cwe | 是 | 格式 CWE-XXX |
| attack_info.attack_path | 是 | 非空 |
| attack_info.poc_method | 是 | 非空 |
| mitigation.strategy | 是 | 非空 |

**补充动作**:

1. **代码位置缺失**:
   ```bash
   # 使用 Grep/Read 工具定位
   Grep --pattern "vulnerability_pattern" --path project/
   ```

2. **CWE/CAPEC缺失**:
   ```bash
   # 查询KB
   $SKILL_PATH/kb --semantic-search "threat description" --search-type cwe
   ```

3. **缓解措施缺失**:
   ```bash
   # 查询KB
   $SKILL_PATH/kb --cwe CWE-XXX --mitigations
   ```

**输出**: verified_risks[] (完整)
```

---

## 6. 报告类型定义 (要求3)

### 6.1 报告命名规范

```yaml
# report-naming.schema.yaml
naming_convention:
  pattern: "{PROJECT}-{REPORT_TYPE}.md"
  project_name:
    source: "从 project_context 提取或用户指定"
    format: "UPPERCASE, 连字符分隔"
    example: "N8N, MY-PROJECT, WEBAPP-V2"
  report_type:
    format: "UPPERCASE, 连字符分隔"

output_location:
  primary: "项目根目录"
  alternative: "tmp_data/ 目录"
```

### 6.2 8种标准报告定义

| # | 报告类型 | 文件名 | 主要内容 | 主要来源 |
|---|----------|--------|---------|---------|
| 1 | 主报告 | `{PROJECT}-THREAT-MODEL-REPORT.md` | 完整威胁模型，包含所有章节 | P1-P8 全部 |
| 2 | 架构分析 | `{PROJECT}-ARCHITECTURE-ANALYSIS.md` | 系统架构、组件拓扑、技术栈 | P1, P2 |
| 3 | DFD图 | `{PROJECT}-DFD-DIAGRAM.md` | 数据流图、元素清单、信任边界 | P2, P3 |
| 4 | 风险清单 | `{PROJECT}-RISK-INVENTORY.md` | **完整风险清单 + 每个风险的详情块** | P5, P6 |
| 5 | 缓解措施 | `{PROJECT}-MITIGATION-MEASURES.md` | 缓解建议、代码示例、路线图 (仅优先级，无时间估计) | P7 |
| 6 | 合规报告 | `{PROJECT}-COMPLIANCE-REPORT.md` | 风险-合规框架映射 | P5, P7 |
| 7 | 攻击验证 | `{PROJECT}-ATTACK-PATH-VALIDATION.md` | 攻击路径、POC方法、验证结果 | P6 |
| 8 | 渗透计划 | `{PROJECT}-PENETRATION-TEST-PLAN.md` | 完整渗透测试计划、测试用例 | P6, P7 |

### 6.3 各报告内容结构

#### 报告1: 主报告 (THREAT-MODEL-REPORT.md)

```markdown
# 威胁模型报告: {PROJECT}

**评估时间**: YYYY-MM-DD HH:MM:SS
**分析师**: Claude (STRIDE Deep Threat Modeling)
**版本**: 1.0

---

## 1. 执行摘要
### 1.1 项目概述
### 1.2 评估结论 (统计表)
### 1.3 关键发现 (Top 3-5)
### 1.4 立即行动建议

## 2. 系统架构概览
### 2.1 组件拓扑 (ASCII)
### 2.2 数据流图 (ASCII)
### 2.3 信任边界
### 2.4 技术栈

## 3. 安全功能设计评估
### 3.1 评估矩阵 (9域)
### 3.2 关键安全发现详情

## 4. STRIDE 威胁分析
### 4.1 威胁汇总表 (按STRIDE分类)
### 4.2-4.7 各STRIDE类别表格
### 4.X 威胁详细分析 (每个Critical/High风险)

## 5. 威胁优先级矩阵
### 5.1 风险评估矩阵
### 5.2 攻击面热力图

## 6. 缓解措施建议
### 6.1 P0 - 立即修复
### 6.2 P1 - 紧急
### 6.3 P2 - 高优先级
### 6.4 实施路线图 (仅优先级，无时间估计)

## 7. 合规性映射
### 7.1 OWASP Top 10 映射
### 7.2 OWASP LLM Top 10 映射 (如适用)

## 附录
### A. DFD元素完整清单
### B. Mermaid DFD 源码
### C. 威胁完整清单
### D. 知识库查询记录
### E. 参考资料
```

#### 报告4: 风险清单 (RISK-INVENTORY.md)

```markdown
# 风险清单: {PROJECT}

**评估时间**: YYYY-MM-DD HH:MM:SS
**总风险数**: XX
**版本**: 1.0

---

## 1. 风险统计摘要

### 1.1 按严重程度
| 严重程度 | 数量 | 百分比 |
|---------|------|--------|
| 🔴 Critical | X | X% |
| 🟠 High | X | X% |
| 🟡 Medium | X | X% |
| 🟢 Low | X | X% |

### 1.2 按STRIDE类别
| STRIDE | 数量 | Critical | High | Medium | Low |
|--------|------|----------|------|--------|-----|
| Spoofing | X | X | X | X | X |
| Tampering | X | X | X | X | X |
| ... | | | | | |

### 1.3 按组件
| 组件 | 风险数 | 最高等级 |
|------|--------|---------|
| [组件1] | X | Critical |
| [组件2] | X | High |

---

## 2. 风险汇总表

| 威胁ID | STRIDE | 元素 | 风险名称 | CWE | 严重程度 | 状态 |
|--------|--------|------|---------|-----|---------|------|
| T-S-P01-001 | S | P01 | [名称] | CWE-XXX | 🔴 Critical | 待修复 |
| T-T-DS01-001 | T | DS01 | [名称] | CWE-XXX | 🟠 High | 待修复 |
| ... | | | | | | |

---

## 3. 风险详情

### T-S-P01-001: [风险名称]
[完整风险详情块，按标准格式]

---

### T-T-DS01-001: [风险名称]
[完整风险详情块，按标准格式]

---

[... 所有风险的详情块 ...]
```

#### 报告5: 缓解措施 (MITIGATION-MEASURES.md)

```markdown
# 缓解措施报告: {PROJECT}

**评估时间**: YYYY-MM-DD HH:MM:SS
**总措施数**: XX
**版本**: 1.0

---

## 1. 缓解优先级矩阵

### 1.1 按优先级分组
| 优先级 | 措施数 | 风险数 | 风险降低 |
|--------|--------|--------|---------|
| P0 - 立即 | X | X | XX% |
| P1 - 紧急 | X | X | XX% |
| P2 - 高 | X | X | XX% |
| P3 - 中 | X | X | XX% |

---

## 2. P0 - 立即修复措施

### M-001: [措施名称]

**针对威胁**: T-X-XX-XXX
**风险降低**: XX%

**当前状态**:
[问题描述]

**推荐控制**:
[缓解策略]

```language
// 实现代码示例
secure_code();
```

**实施步骤**:
1. [步骤1]
2. [步骤2]
3. [步骤3]

**依赖**: [无/Redis/...]

---

## 3. P1 - 紧急措施
[同上格式...]

## 4. P2 - 高优先级措施
[同上格式...]

## 5. P3 - 中优先级措施
[同上格式...]

---

## 6. 实施路线图

### 6.1 按优先级排序
| 优先级 | 措施 | 依赖 | 资源需求 |
|--------|------|------|---------|
| P0 | M-001, M-002 | 无 | [人天] |
| P1 | M-003, M-004 | M-001 | [人天] |
| P2 | M-005, M-006 | M-003 | [人天] |

### 6.2 防御纵深架构
[ASCII 图]

---

## 7. 合规映射
| 措施 | NIST CSF | ISO 27001 | OWASP |
|------|----------|-----------|-------|
| M-001 | PR.DS-1 | A.10.1.1 | A3:2021 |
| ... | | | |
```

#### 报告8: 渗透测试计划 (PENETRATION-TEST-PLAN.md)

```markdown
# 渗透测试计划: {PROJECT}

> **文档版本**: 1.0
> **创建日期**: YYYY-MM-DD HH:MM:SS
> **分类**: 机密 - 安全测试
> **授权范围**: 仅限授权测试环境

---

## 1. 测试概述

### 1.1 测试目标
| 漏洞编号 | 名称 | CVSS | 目标组件 |
|----------|------|------|----------|
| V-001 | [漏洞名称] | X.X | `path/to/component/` |
| V-002 | [漏洞名称] | X.X | `path/to/component/` |

### 1.2 技术架构分析
[ASCII 图 - 攻击路径可视化]

---

## 2. V-001: [漏洞名称] 渗透测试

### 2.1 漏洞技术分析

#### 2.1.1 源代码关键位置
| 文件 | 功能 | 安全风险 |
|------|------|----------|
| `file.py:L89-120` | [功能] | [风险] |

#### 2.1.2 攻击向量分析
**向量 A: [攻击名称]**
```
攻击复杂度: 低/中/高
前提条件: [...]
风险: [...]
```

### 2.2 渗透测试用例

#### TC-XXX-001: [测试名称]

**目标**: [测试目标]

**前置条件**:
- [条件1]
- [条件2]

**测试步骤**:
```language
// 步骤 1: [描述]
test_code_step_1();

// 步骤 2: [描述]
test_code_step_2();
```

**测试 Payload**:
```
Payload 1 - [描述]:
[payload内容]

Payload 2 - [描述]:
[payload内容]
```

**预期结果**: [...]

**实际结果**: `[待填写]`

**判定标准**:
- PASS: [条件]
- FAIL: [条件]

### 2.3 测试矩阵
| 测试用例 | 攻击向量 | 优先级 | 预计时间 |
|----------|----------|--------|----------|
| TC-XXX-001 | [向量] | P0 | Xh |
| TC-XXX-002 | [向量] | P1 | Xh |

---

## 3. 测试环境准备

### 3.1 隔离测试环境
```yaml
# docker-compose.test.yml
version: '3.8'
services:
  # [测试环境配置]
```

### 3.2 测试数据准备
```sql
-- 测试数据初始化
CREATE TABLE ...
```

### 3.3 监控配置
[监控配置代码]

---

## 4. 风险评估与缓解

### 4.1 测试风险矩阵
| 风险类型 | 可能性 | 影响 | 缓解措施 |
|----------|--------|------|----------|
| [风险] | 低/中/高 | 低/中/高 | [措施] |

### 4.2 测试终止条件
- [条件1]
- [条件2]

### 4.3 发现报告流程
```
发现漏洞 → 停止测试 → 记录复现步骤 → 评估 CVSS → 准备 POC → 48h 内报告
```

---

## 附录

### A. CVSS 评分
### B. 相关 CVE
```

---

## 7. 质量门禁

### 7.1 风险详情完整性检查

```yaml
# 每个风险必须包含以下字段
required_fields:
  - id                      # 威胁ID
  - name                    # 风险名称
  - stride_category         # STRIDE分类
  - element_id              # 受影响元素
  - description.brief       # 简述
  - description.detailed    # 详细描述
  - location.component      # 组件名称
  - location.file           # 文件位置
  - cause_analysis.root_cause  # 根本原因
  - cause_analysis.related_cwe # CWE映射
  - attack_info.attack_path    # 攻击路径
  - attack_info.poc_method     # POC方法
  - impact.cvss_score          # CVSS评分
  - mitigation.priority        # 优先级
  - mitigation.strategy        # 缓解策略

# 字段完整性最低要求
completeness_threshold: 95%
```

### 7.2 报告一致性检查

```yaml
consistency_checks:
  - name: "风险清单与详情一致性"
    rule: "汇总表中的每个风险ID必须有对应的详情块"

  - name: "统计数据准确性"
    rule: "按严重程度/STRIDE分类的统计必须与风险清单一致"

  - name: "缓解措施完整性"
    rule: "每个Critical/High风险必须有对应的缓解措施"

  - name: "攻击路径完整性"
    rule: "每个Critical/High风险必须有攻击路径描述"
```

---

## 8. 实施计划

### 8.1 文件变更清单

| 文件 | 变更类型 | 描述 |
|------|---------|------|
| `SKILL.md` | 修改 | 更新 Phase 8 章节引用新工作流 |
| `WORKFLOW.md` | 修改 | 重写 Phase 8 详细工作流 |
| `assets/templates/` | 新增 | 创建 8 个报告模板文件 |
| `assets/schemas/` | 新增 | 创建数据格式定义文件 |

### 8.2 变更影响

- **Phase 1-7**: 增加阶段结束风险汇总要求
- **Phase 8**: 完全重构工作流
- **输出**: 从 1 个报告变为 8 个标准化报告

---

## 9. 评审要点

请评审以下内容:

1. **三层架构设计** (流程/模板/规范分离) 是否合理?
2. **阶段风险汇总机制** 是否足够捕获风险信息?
3. **风险详情标准格式** 是否包含所有必要字段?
4. **P8 新工作流** 步骤是否清晰完整?
5. **8种报告定义** 是否满足需求?
6. **质量门禁** 是否足够严格?

---

**文档结束**

> 请提供评审意见，批准后开始实施。
