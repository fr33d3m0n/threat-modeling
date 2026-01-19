# Report Naming Schema

> **版本**: 1.5.0
> **最后更新**: 2026-01-02
> **所属模块**: Report Module v2.0.4

---

## 1. 概述

本文档定义威胁建模报告的标准命名规范、报告类型和输出位置。

**设计目标**:
- 统一报告命名格式
- 明确 8 种报告类型定义
- 规范输出目录结构

---

## 2. 命名规范

### 2.1 基本格式

```
{PROJECT}-{REPORT_TYPE}.md
```

### 2.2 PROJECT 规范

```yaml
project_name:
  source: |
    1. 用户显式指定
    2. 从 project_context.name 提取
    3. 从项目根目录 package.json/pyproject.toml 提取
    4. 从项目目录名推断

  format:
    case: "UPPERCASE"
    separator: "-"
    max_length: 30
    allowed_chars: "[A-Z0-9-]"

  examples:
    - "N8N"
    - "MY-PROJECT"
    - "WEBAPP-V2"
    - "TRADING-PLATFORM"

  invalid_examples:
    - "my_project"    # 下划线不允许
    - "MyProject"     # 混合大小写不允许
    - "my project"    # 空格不允许
```

### 2.3 REPORT_TYPE 规范

```yaml
# v2.0.0 标准 8 种报告类型
report_types:
  - id: "main"
    type: "RISK-ASSESSMENT-REPORT"
    description: "主综合报告"
    required: true
    template: "assets/templates/RISK-ASSESSMENT-REPORT.template.md"

  - id: "arch"
    type: "ARCHITECTURE-ANALYSIS"
    description: "架构分析报告"
    required: false
    template: "assets/templates/ARCHITECTURE-ANALYSIS.template.md"

  - id: "dfd"
    type: "DFD-ANALYSIS"
    description: "数据流分析报告"
    required: false
    template: "assets/templates/DFD-ANALYSIS.template.md"

  - id: "boundary"
    type: "TRUST-BOUNDARY-ANALYSIS"
    description: "信任边界分析报告"
    required: false
    template: "assets/templates/TRUST-BOUNDARY-ANALYSIS.template.md"

  - id: "design"
    type: "SECURITY-DESIGN-REVIEW"
    description: "安全设计评审报告"
    required: false
    template: "assets/templates/SECURITY-DESIGN-REVIEW.template.md"

  - id: "risk"
    type: "RISK-INVENTORY"
    description: "风险清单报告"
    required: true
    template: "assets/templates/RISK-INVENTORY.template.md"

  - id: "attack"
    type: "ATTACK-PATH-VALIDATION"
    description: "攻击路径验证报告"
    required: false
    template: "assets/templates/ATTACK-PATH-VALIDATION.template.md"

  - id: "mitigation"
    type: "MITIGATION-MEASURES"
    description: "缓解措施报告"
    required: true
    template: "assets/templates/MITIGATION-MEASURES.template.md"

  - id: "pentest"
    type: "PENETRATION-TEST-PLAN"
    description: "渗透测试方案"
    required: true
    template: "assets/templates/PENETRATION-TEST-PLAN.template.md"
```

---

## 3. 标准报告定义

### 3.1 报告类型矩阵 (v2.0.0)

| # | 报告ID | 文件名模式 | 主要内容 | 主要来源阶段 | 必需 |
|---|--------|-----------|---------|-------------|------|
| 1 | main | `{PROJECT}-RISK-ASSESSMENT-REPORT.md` | 完整威胁模型，包含所有章节 | P1-P8 全部 | ✅ |
| 2 | risk | `{PROJECT}-RISK-INVENTORY.md` | 完整风险清单 + 每个风险详情块 | P5, P6 | ✅ |
| 3 | mitigation | `{PROJECT}-MITIGATION-MEASURES.md` | 缓解建议、代码示例、优先级路线图 | P7 | ✅ |
| 4 | pentest | `{PROJECT}-PENETRATION-TEST-PLAN.md` | 渗透测试方案、测试用例、ATT&CK映射 | P6, P7 | ✅ |
| 5 | arch | `{PROJECT}-ARCHITECTURE-ANALYSIS.md` | 系统架构、组件拓扑、技术栈 | P1, P2 | |
| 6 | dfd | `{PROJECT}-DFD-DIAGRAM.md` | 数据流图、元素清单、数据分类 | P2 | |
| 7 | compliance | `{PROJECT}-COMPLIANCE-REPORT.md` | 合规框架映射、差距分析 | P5, P7 | |
| 8 | attack | `{PROJECT}-ATTACK-PATH-VALIDATION.md` | 攻击路径、POC方法、验证结果 | P6 | |

### 3.2 各报告详细定义

#### 报告 1: 主报告 (RISK-ASSESSMENT-REPORT)

```yaml
report_main:
  id: "main"
  filename: "{PROJECT}-RISK-ASSESSMENT-REPORT.md"
  description: "威胁模型主报告，包含完整分析结果"

  primary_sources:
    - P1: project_context
    - P2: dfd_elements
    - P3: boundary_context
    - P4: security_gaps
    - P5: threat_inventory
    - P6: validated_threats
    - P7: mitigation_plan

  structure:
    - section: "1. 执行摘要"
      subsections:
        - "1.1 项目概述"
        - "1.2 评估结论 (统计表)"
        - "1.3 关键发现 (Top 3-5)"
        - "1.4 立即行动建议"

    - section: "2. 系统架构概览"
      subsections:
        - "2.1 组件拓扑 (ASCII)"
        - "2.2 数据流图 (ASCII)"
        - "2.3 信任边界"
        - "2.4 技术栈"

    - section: "3. 安全功能设计评估"
      subsections:
        - "3.1 评估矩阵 (9域)"
        - "3.2 关键安全发现详情"

    - section: "4. STRIDE 威胁分析"
      subsections:
        - "4.1 威胁汇总表 (按STRIDE分类)"
        - "4.2-4.7 各STRIDE类别详细表格"
        - "4.X 威胁详细分析 (Critical/High 风险)"

    - section: "5. 威胁优先级矩阵"
      subsections:
        - "5.1 风险评估矩阵"
        - "5.2 攻击面热力图"

    - section: "6. 缓解措施建议"
      subsections:
        - "6.1 P0 - 立即修复"
        - "6.2 P1 - 紧急"
        - "6.3 P2 - 高优先级"
        - "6.4 实施路线图 (仅优先级，无时间估计)"

    - section: "7. 合规性映射"
      subsections:
        - "7.1 OWASP Top 10 映射"
        - "7.2 OWASP LLM Top 10 映射 (如适用)"

    - section: "附录"
      subsections:
        - "A. DFD元素完整清单"
        - "B. Mermaid DFD 源码"
        - "C. 威胁完整清单"
        - "D. 知识库查询记录"
        - "E. 参考资料"

  length_estimate: "50-100 页"
```

#### 报告 2: 架构分析 (ARCHITECTURE-ANALYSIS)

```yaml
report_arch:
  id: "arch"
  filename: "{PROJECT}-ARCHITECTURE-ANALYSIS.md"
  description: "系统架构和技术栈分析"

  primary_sources:
    - P1: project_context
    - P2: dfd_elements

  structure:
    - section: "1. 项目概述"
      subsections:
        - "1.1 项目类型和目的"
        - "1.2 技术栈摘要"
        - "1.3 代码结构概览"

    - section: "2. 组件拓扑"
      subsections:
        - "2.1 高层架构图 (ASCII)"
        - "2.2 模块依赖关系"
        - "2.3 外部服务集成"

    - section: "3. 技术栈详情"
      subsections:
        - "3.1 编程语言和框架"
        - "3.2 数据库和存储"
        - "3.3 消息队列和缓存"
        - "3.4 安全相关组件"

    - section: "4. 安全相关模块"
      subsections:
        - "4.1 认证模块"
        - "4.2 授权模块"
        - "4.3 加密模块"
        - "4.4 日志和审计模块"

    - section: "5. 初始攻击面"
      subsections:
        - "5.1 外部入口点"
        - "5.2 API 端点"
        - "5.3 敏感数据位置"

  length_estimate: "15-25 页"
```

#### 报告 3: DFD 图 (DFD-DIAGRAM)

```yaml
report_dfd:
  id: "dfd"
  filename: "{PROJECT}-DFD-DIAGRAM.md"
  description: "数据流图和信任边界分析"

  primary_sources:
    - P2: dfd_elements
    - P3: boundary_context

  structure:
    - section: "1. DFD 概览"
      subsections:
        - "1.1 Level 0 上下文图"
        - "1.2 Level 1 系统图"

    - section: "2. DFD 元素清单"
      subsections:
        - "2.1 进程 (Processes)"
        - "2.2 数据存储 (Data Stores)"
        - "2.3 数据流 (Data Flows)"
        - "2.4 外部实体 (External Entities)"

    - section: "3. 信任边界"
      subsections:
        - "3.1 边界定义"
        - "3.2 边界穿越分析"
        - "3.3 关键接口"

    - section: "4. 敏感数据流"
      subsections:
        - "4.1 PII 数据流"
        - "4.2 凭证数据流"
        - "4.3 其他敏感数据"

    - section: "附录"
      subsections:
        - "A. Mermaid DFD 源码"
        - "B. 元素属性详情"

  length_estimate: "10-20 页"
```

#### 报告 4: 风险清单 (RISK-INVENTORY)

```yaml
report_risk:
  id: "risk"
  filename: "{PROJECT}-RISK-INVENTORY.md"
  description: "完整风险清单和每个风险的详情块"

  primary_sources:
    - P5: threat_inventory
    - P6: validated_threats

  structure:
    - section: "1. 风险统计摘要"
      subsections:
        - "1.1 按严重程度统计"
        - "1.2 按 STRIDE 类别统计"
        - "1.3 按组件分布统计"

    - section: "2. 风险汇总表"
      content: "所有风险的表格列表"

    - section: "3. 风险详情"
      content: "每个风险的完整详情块 (按 risk-detail.schema.md)"
      per_risk_sections:
        - "基本信息"
        - "风险描述"
        - "位置定位"
        - "原因分析"
        - "攻击路径"
        - "影响评估"
        - "缓解措施"

  notes:
    - "每个 Critical/High 风险必须有完整详情块"
    - "Medium/Low 风险可以使用简化格式"

  length_estimate: "30-80 页 (取决于风险数量)"
```

#### 报告 5: 缓解措施 (MITIGATION-MEASURES)

```yaml
report_mitigation:
  id: "mitigation"
  filename: "{PROJECT}-MITIGATION-MEASURES.md"
  description: "缓解措施建议和实施路线图"

  primary_sources:
    - P7: mitigation_plan

  structure:
    - section: "1. 缓解优先级矩阵"
      subsections:
        - "1.1 按优先级分组统计"
        - "1.2 风险降低预估"

    - section: "2. P0 - 立即修复措施"
      per_measure:
        - "针对威胁"
        - "当前状态"
        - "推荐控制"
        - "实现代码示例"
        - "实施步骤"
        - "依赖项"

    - section: "3. P1 - 紧急措施"
      content: "同 P0 格式"

    - section: "4. P2 - 高优先级措施"
      content: "同 P0 格式"

    - section: "5. P3 - 中优先级措施"
      content: "同 P0 格式"

    - section: "6. 实施路线图"
      subsections:
        - "6.1 按优先级排序"
        - "6.2 依赖关系"
        - "6.3 防御纵深架构图"

    - section: "7. 合规映射"
      content: "措施与合规框架对应表"

  notes:
    - "只包含优先级，不包含时间估计"
    - "代码示例必须是可直接使用的生产代码"

  length_estimate: "20-40 页"
```

#### 报告 6: 合规报告 (COMPLIANCE-REPORT)

```yaml
report_compliance:
  id: "compliance"
  filename: "{PROJECT}-COMPLIANCE-REPORT.md"
  description: "风险与合规框架的映射分析"

  primary_sources:
    - P5: threat_inventory
    - P7: compliance_mapping

  structure:
    - section: "1. 合规概述"
      subsections:
        - "1.1 适用合规框架"
        - "1.2 合规差距摘要"

    - section: "2. OWASP Top 10 映射"
      content: "风险与 OWASP Top 10 对应表"

    - section: "3. OWASP LLM Top 10 映射"
      condition: "仅当项目包含 AI/LLM 组件时"

    - section: "4. CWE 映射"
      content: "按 CWE 分组的风险清单"

    - section: "5. NIST CSF 映射"
      content: "控制措施与 NIST 控制对应"

    - section: "6. 差距分析"
      subsections:
        - "6.1 未覆盖的控制"
        - "6.2 部分实现的控制"
        - "6.3 建议改进"

  length_estimate: "15-25 页"
```

#### 报告 7: 攻击验证 (ATTACK-PATH-VALIDATION)

```yaml
report_attack:
  id: "attack"
  filename: "{PROJECT}-ATTACK-PATH-VALIDATION.md"
  description: "攻击路径验证和 POC 方法"

  primary_sources:
    - P6: validated_threats
    - P6: attack_paths

  structure:
    - section: "1. 验证概述"
      subsections:
        - "1.1 验证范围"
        - "1.2 验证方法"
        - "1.3 结果摘要"

    - section: "2. 已验证攻击路径"
      per_attack:
        - "攻击路径 ID"
        - "目标威胁"
        - "攻击链描述"
        - "前置条件"
        - "验证步骤"
        - "POC 方法/命令"
        - "验证结果"
        - "可利用性评估"

    - section: "3. 攻击面分析"
      subsections:
        - "3.1 外部攻击面"
        - "3.2 内部攻击面"
        - "3.3 高风险入口点"

    - section: "4. 攻击链可视化"
      content: "攻击链图 (ASCII/Mermaid)"

    - section: "5. 排除项"
      content: "验证后排除的误报"

  length_estimate: "15-30 页"
```

#### 报告 8: 渗透测试计划 (PENETRATION-TEST-PLAN)

```yaml
report_pentest:
  id: "pentest"
  filename: "{PROJECT}-PENETRATION-TEST-PLAN.md"
  description: "完整的渗透测试计划和测试用例"

  primary_sources:
    - P6: validated_threats
    - P7: mitigation_plan

  structure:
    - section: "1. 测试概述"
      subsections:
        - "1.1 测试目标"
        - "1.2 测试范围"
        - "1.3 授权声明"

    - section: "2. 技术架构分析"
      content: "攻击视角的架构图"

    - section: "3. 渗透测试用例"
      per_vulnerability:
        - "漏洞技术分析"
        - "攻击向量分析"
        - "测试用例 (TC-XXX-NNN)"
        - "测试 Payload"
        - "预期结果"
        - "判定标准"
        - "测试矩阵"

    - section: "4. 测试环境准备"
      subsections:
        - "4.1 隔离测试环境"
        - "4.2 测试数据准备"
        - "4.3 监控配置"

    - section: "5. 风险评估与缓解"
      subsections:
        - "5.1 测试风险矩阵"
        - "5.2 测试终止条件"
        - "5.3 发现报告流程"

    - section: "附录"
      subsections:
        - "A. CVSS 评分"
        - "B. 相关 CVE"

  classification: "机密 - 安全测试"
  length_estimate: "25-50 页"
```

---

## 4. 输出位置规范

### 4.1 目录结构

```yaml
output_locations:
  # 最终报告目录
  final_reports:
    path: "{PROJECT_ROOT}/Risk_Assessment_Report/"
    description: "风险评估报告目录"
    use_case: "Phase 8 生成的正式交付物"
    auto_create: true

  # 阶段产物目录 (持久化)
  phase_outputs:
    path: "{PROJECT_ROOT}/Risk_Assessment_Report/.phase_working/"
    description: "阶段中间产物 (持久化工作目录)"
    use_case: "Phase 1-7 输出，支持会话恢复和审计追溯"
    auto_create: true
    hidden: true  # 隐藏目录，不作为交付物

  # 归档目录
  archive:
    path: "{PROJECT_ROOT}/Risk_Assessment_Report/archive/{VERSION}/"
    description: "归档目录"
    use_case: "历史版本存档"
```

### 4.2 输出类型区分

| 类型 | 位置 | 文件名格式 | 说明 |
|------|------|-----------|------|
| **最终报告** | `Risk_Assessment_Report/` | `{PROJECT}-{REPORT_TYPE}.md` | Phase 8 输出的正式交付物 |
| **阶段产物** | `Risk_Assessment_Report/.phase_working/` | `P{N}-{PHASE_NAME}.md` | Phase 1-7 持久化中间结果 |
| **归档报告** | `Risk_Assessment_Report/archive/` | `{PROJECT}-{REPORT_TYPE}.md` | 历史版本存档 |

### 4.3 阶段产物规范

**设计原理**: 阶段产物必须持久化保存，防止上下文丢失、会话中断、信息不完整。

**缓存策略**: 单副本缓存，只保留当前/最新一次分析会话的阶段产物

**阶段产物文件列表**:
| Phase | 文件名 | 主要内容 |
|-------|--------|---------|
| - | `_session_meta.yaml` | 会话元数据 (必需) |
| P1 | `P1-PROJECT-UNDERSTANDING.md` | 项目上下文、技术栈、安全相关模块 |
| P2 | `P2-DFD-ANALYSIS.md` | DFD元素清单、数据分类、Mermaid源码 |
| P3 | `P3-TRUST-BOUNDARY.md` | 信任边界定义、边界穿越、关键接口 |
| P4 | `P4-SECURITY-DESIGN-REVIEW.md` | 9域评估矩阵、安全发现、设计缺陷 |
| P5 | `P5-STRIDE-ANALYSIS.md` | STRIDE矩阵、威胁清单、KB查询记录 |
| P6 | `P6-RISK-VALIDATION.md` | 验证结果、攻击路径、POC方法、误报排除 |
| P7 | `P7-MITIGATION-PLANNING.md` | 缓解计划、优先级矩阵、防御架构 |

**会话元数据 (_session_meta.yaml)** - 必需:
```yaml
session:
  project_name: "N8N"                           # 项目名称
  session_id: "20251230-100000"                 # 会话ID (YYYYMMDD-HHMMSS)
  started_at: "2025-12-30T10:00:00+08:00"       # ISO 8601 时间戳
  last_updated: "2025-12-30T14:32:15+08:00"     # 最后更新时间
  framework_version: "v2.0.0"                   # 框架版本
  analyst: "Claude (STRIDE Deep Threat Modeling)"
  status: "in_progress"                         # in_progress | completed | failed

phases:
  P1: { status: "completed", completed_at: "2025-12-30T10:15:32+08:00" }
  P2: { status: "completed", completed_at: "2025-12-30T10:45:18+08:00" }
  P3: { status: "in_progress", started_at: "2025-12-30T11:00:00+08:00" }
  P4: { status: "pending" }
  P5: { status: "pending" }
  P6: { status: "pending" }
  P7: { status: "pending" }
  P8: { status: "pending" }
```

**阶段产物文件头部 (YAML front matter)**:
```yaml
---
phase: 1
name: "PROJECT-UNDERSTANDING"
project: "N8N"
session_id: "20251230-100000"
completed_at: "2025-12-30T10:15:32+08:00"
framework_version: "v2.0.0"
---
```

**缓存管理规则**:
| 场景 | 行为 |
|------|------|
| 新会话 + 目录不存在 | 创建目录，初始化 `_session_meta.yaml` |
| 新会话 + 同一项目 | 提示：继续上次会话 / 覆盖重新开始 |
| 新会话 + 不同项目 | 清空目录，开始新会话 |
| 会话完成后 | 保留 `.phase_working/` 作为审计记录 |

### 4.4 完整输出示例

```
project-root/
├── Risk_Assessment_Report/                  # ✅ 报告输出目录
│   │
│   │  ┌─ 必需报告 (4份) ──────────────────────────────────────────────┐
│   ├── N8N-RISK-ASSESSMENT-REPORT.md        # 风险评估报告 (主报告)
│   ├── N8N-RISK-INVENTORY.md                # 风险清单
│   ├── N8N-MITIGATION-MEASURES.md           # 缓解措施
│   ├── N8N-PENETRATION-TEST-PLAN.md         # 渗透测试方案
│   │  └──────────────────────────────────────────────────────────────┘
│   │
│   │  ┌─ 可选报告 (按需生成) ─────────────────────────────────────────┐
│   ├── N8N-ARCHITECTURE-ANALYSIS.md         # 架构分析
│   ├── N8N-DFD-DIAGRAM.md                   # DFD图
│   ├── N8N-COMPLIANCE-REPORT.md             # 合规报告
│   ├── N8N-ATTACK-PATH-VALIDATION.md        # 攻击路径验证
│   │  └──────────────────────────────────────────────────────────────┘
│   │
│   │  ┌─ 阶段过程文档 (自动发布，保留英文名) ─────────────────────────┐
│   ├── P1-PROJECT-UNDERSTANDING.md          # Phase 1 项目理解
│   ├── P2-DFD-ANALYSIS.md                   # Phase 2 DFD分析
│   ├── P3-TRUST-BOUNDARY.md                 # Phase 3 信任边界
│   ├── P4-SECURITY-DESIGN-REVIEW.md         # Phase 4 安全设计评估
│   ├── P5-STRIDE-THREATS.md                 # Phase 5 STRIDE威胁分析
│   ├── P6-RISK-VALIDATION.md                # Phase 6 风险验证
│   │  └──────────────────────────────────────────────────────────────┘
│   │
│   ├── .phase_working/                      # 阶段工作目录 (隐藏)
│   │   ├── P1-PROJECT-UNDERSTANDING.md
│   │   ├── P2-DFD-ANALYSIS.md
│   │   ├── P3-TRUST-BOUNDARY.md
│   │   ├── P4-SECURITY-DESIGN-REVIEW.md
│   │   ├── P5-STRIDE-THREATS.md
│   │   ├── P6-RISK-VALIDATION.md
│   │   ├── P7-MITIGATION-PLAN.md
│   │   └── _session_meta.yaml               # 会话元数据
│   │
│   └── archive/                             # 归档目录
│       └── v1.0.0/
│           └── N8N-RISK-ASSESSMENT-REPORT.md
└── src/                                     # 项目源代码 (被评估对象)
```

### 4.5 命名验证规则

```yaml
naming_validation:
  # === 最终报告命名规则 (Risk_Assessment_Report/) ===
  final_report:
    project_name:
      regex: "^[A-Z][A-Z0-9-]{0,29}$"
      description: "大写字母开头，可包含大写字母、数字、连字符"
      max_length: 30
      examples:
        valid: ["N8N", "OPEN-WEBUI", "MY-PROJECT-V2"]
        invalid: ["n8n", "my_project", "MyProject"]

    report_type:
      allowed_values:
        - "RISK-ASSESSMENT-REPORT"
        - "RISK-INVENTORY"
        - "MITIGATION-MEASURES"
        - "PENETRATION-TEST-PLAN"
        - "ARCHITECTURE-ANALYSIS"
        - "DFD-DIAGRAM"
        - "COMPLIANCE-REPORT"
        - "ATTACK-PATH-VALIDATION"

    file_pattern:
      regex: "^[A-Z][A-Z0-9-]{0,29}-(RISK-ASSESSMENT-REPORT|RISK-INVENTORY|MITIGATION-MEASURES|PENETRATION-TEST-PLAN|ARCHITECTURE-ANALYSIS|DFD-DIAGRAM|COMPLIANCE-REPORT|ATTACK-PATH-VALIDATION)\\.md$"

  # === 阶段产物命名规则 (.phase_working/) ===
  phase_output:
    file_pattern:
      regex: "^P[1-7]-[A-Z][A-Z0-9-]+\\.md$"
      description: "P{N}-{PHASE_NAME}.md 格式"
    allowed_files:
      - "P1-PROJECT-UNDERSTANDING.md"
      - "P2-DFD-ANALYSIS.md"
      - "P3-TRUST-BOUNDARY.md"
      - "P4-SECURITY-DESIGN-REVIEW.md"
      - "P5-STRIDE-ANALYSIS.md"
      - "P6-RISK-VALIDATION.md"
      - "P7-MITIGATION-PLANNING.md"
      - "_session_meta.yaml"

  # === 禁止的命名模式 (仅适用于最终报告目录) ===
  forbidden_in_final_reports:
    - "P{N}-*.md"               # 阶段编号开头 → 应在 .phase_working/
    - "PHASE{N}-*.md"           # PHASE 开头
    - "*-PHASE-*.md"            # 包含 PHASE
    - "phase*.md"               # 小写 phase
    - "*_*.md"                  # 下划线分隔
```

---

## 5. 报告元数据

### 5.1 通用元数据格式

```yaml
# 每份报告头部必须包含
report_metadata:
  project_name: string
  report_type: string
  version: string
  assessment_datetime: "YYYY-MM-DD HH:MM:SS"
  analyst: "Claude (STRIDE Deep Threat Modeling)"
  framework_version: "STRIDE-TM v1.0.2"

  # 统计摘要 (根据报告类型)
  summary:
    total_threats: integer       # 总威胁数
    critical: integer            # Critical 数量
    high: integer                # High 数量
    medium: integer              # Medium 数量
    low: integer                 # Low 数量
```

### 5.2 Markdown 元数据块模板

```markdown
# {报告类型}: {PROJECT}

> **评估时间**: YYYY-MM-DD HH:MM:SS
> **分析师**: Claude (STRIDE Deep Threat Modeling)
> **框架版本**: STRIDE-TM v1.0.2
> **报告版本**: 1.0

---
```

---

## 6. 报告生成规则

### 6.1 必需报告

以下报告在每次完整评估中必须生成:

| 报告 | 条件 |
|------|------|
| RISK-ASSESSMENT-REPORT | 始终生成 |
| RISK-INVENTORY | 始终生成 |
| MITIGATION-MEASURES | 始终生成 |
| PENETRATION-TEST-PLAN | 始终生成 (基于P6风险验证数据) |

### 6.2 可选报告

以下报告根据条件生成:

| 报告 | 生成条件 |
|------|---------|
| ARCHITECTURE-ANALYSIS | 用户请求或复杂系统 |
| DFD-DIAGRAM | 用户请求或 DFD 元素 > 10 |
| COMPLIANCE-REPORT | 用户请求或有合规需求 |
| ATTACK-PATH-VALIDATION | 有 Critical/High 威胁 |

### 6.3 报告间依赖

```
┌─────────────────────────────────────────────────────────────────┐
│                     Report Dependencies                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  RISK-ASSESSMENT-REPORT (主报告)                                    │
│         │                                                        │
│         ├──→ 引用 ARCHITECTURE-ANALYSIS (章节 2)                 │
│         ├──→ 引用 DFD-DIAGRAM (章节 2.2, 附录 A/B)               │
│         ├──→ 引用 RISK-INVENTORY (章节 4)                        │
│         ├──→ 引用 MITIGATION-MEASURES (章节 6)                   │
│         └──→ 引用 COMPLIANCE-REPORT (章节 7)                     │
│                                                                  │
│  独立报告:                                                       │
│  - ATTACK-PATH-VALIDATION                                        │
│  - PENETRATION-TEST-PLAN                                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. 版本历史

| 版本 | 日期 | 变更说明 |
|------|------|---------|
| 1.4.0 | 2025-12-31 | 渗透测试方案升级为必需报告；阶段过程文档发布保留英文名；重组报告类型表 |
| 1.3.0 | 2025-12-30 | 单副本缓存策略：添加时间戳/版本元数据，定义 `_session_meta.yaml` 和文件头部规范 |
| 1.2.0 | 2025-12-30 | 阶段产物持久化设计：添加 `.phase_working/` 目录，定义 P{N}-{NAME}.md 命名规范 |
| 1.1.0 | 2025-12-30 | 更新输出目录为 `Risk_Assessment_Report/`，添加命名验证规则，区分阶段产物与最终报告 |
| 1.0.0 | 2025-12-26 | 初始版本，定义 8 种报告命名规范 |

---

**文档结束**
