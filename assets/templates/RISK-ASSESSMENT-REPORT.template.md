<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

# 风险评估报告: {PROJECT_NAME}

> **评估时间**: {ASSESSMENT_DATETIME}
> **分析师**: Claude (STRIDE Deep Threat Modeling)
> **框架版本**: STRIDE-TM v2.0.2
> **报告版本**: {REPORT_VERSION}

---

## 1. 执行摘要

### 1.1 项目概述

#### 基本信息

| 属性 | 值 |
|------|-----|
| **项目名称** | {PROJECT_NAME} |
| **项目类型** | {PROJECT_TYPE} |
| **技术栈** | {TECH_STACK} |
| **评估范围** | {ASSESSMENT_SCOPE} |
| **项目仓库** | {PROJECT_REPO} |

#### 项目规模指标

| 指标 | 数值 | 说明 |
|------|------|------|
| **代码总行数** | {TOTAL_LOC} | 不含空行和注释 |
| **文件总数** | {TOTAL_FILES} | 源代码文件 |
| **目录数** | {TOTAL_DIRS} | 代码目录 |
| **主要模块数** | {MODULE_COUNT} | 顶层功能模块 |
| **依赖数量** | {DEPENDENCY_COUNT} | 直接依赖 |

#### 语言分布

| 语言 | 文件数 | 代码行数 | 占比 |
|------|--------|---------|------|
| {LANG_1} | {LANG_1_FILES} | {LANG_1_LOC} | {LANG_1_PCT}% |
| {LANG_2} | {LANG_2_FILES} | {LANG_2_LOC} | {LANG_2_PCT}% |
| {LANG_3} | {LANG_3_FILES} | {LANG_3_LOC} | {LANG_3_PCT}% |
| **合计** | **{TOTAL_FILES}** | **{TOTAL_LOC}** | **100%** |

<!--
语言统计示例:
| TypeScript | 523 | 45,230 | 58% |
| Python     | 87  | 12,450 | 16% |
| JavaScript | 156 | 8,320  | 11% |
| Go         | 45  | 6,780  | 9%  |
| Other      | 89  | 4,670  | 6%  |

使用工具获取: cloc, tokei, scc
-->

#### 安全相关模块

| 模块路径 | 功能 | 文件数 | 安全等级 |
|---------|------|--------|---------|
| {SEC_MODULE_1_PATH} | {SEC_MODULE_1_FUNC} | {SEC_MODULE_1_FILES} | {SEC_MODULE_1_LEVEL} |
| {SEC_MODULE_2_PATH} | {SEC_MODULE_2_FUNC} | {SEC_MODULE_2_FILES} | {SEC_MODULE_2_LEVEL} |
| {SEC_MODULE_3_PATH} | {SEC_MODULE_3_FUNC} | {SEC_MODULE_3_FILES} | {SEC_MODULE_3_LEVEL} |

<!--
安全模块识别关键词: auth, security, crypto, session, token, access, permission
安全等级: 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low
-->

### 1.2 评估结论

#### 威胁统计

| 严重程度 | 数量 | 百分比 | 说明 |
|---------|------|--------|------|
| 🔴 **Critical** | {CRITICAL_COUNT} | {CRITICAL_PCT}% | 需立即修复 |
| 🟠 **High** | {HIGH_COUNT} | {HIGH_PCT}% | 7天内修复 |
| 🟡 **Medium** | {MEDIUM_COUNT} | {MEDIUM_PCT}% | 30天内修复 |
| 🟢 **Low** | {LOW_COUNT} | {LOW_PCT}% | 计划中修复 |
| **总计** | **{TOTAL_COUNT}** | **100%** | |

#### STRIDE 分布

| STRIDE 类型 | 数量 | Critical | High | Medium | Low |
|-------------|------|----------|------|--------|-----|
| **S** - Spoofing | {S_COUNT} | {S_CRITICAL} | {S_HIGH} | {S_MEDIUM} | {S_LOW} |
| **T** - Tampering | {T_COUNT} | {T_CRITICAL} | {T_HIGH} | {T_MEDIUM} | {T_LOW} |
| **R** - Repudiation | {R_COUNT} | {R_CRITICAL} | {R_HIGH} | {R_MEDIUM} | {R_LOW} |
| **I** - Info Disclosure | {I_COUNT} | {I_CRITICAL} | {I_HIGH} | {I_MEDIUM} | {I_LOW} |
| **D** - DoS | {D_COUNT} | {D_CRITICAL} | {D_HIGH} | {D_MEDIUM} | {D_LOW} |
| **E** - EoP | {E_COUNT} | {E_CRITICAL} | {E_HIGH} | {E_MEDIUM} | {E_LOW} |

### 1.3 Critical 风险清单

> **说明**: 以下列出所有 Critical 级别风险，需立即处理。

| 序号 | 风险ID | 风险名称 | STRIDE | 元素 | CWE | CVSS | 修复状态 |
|------|--------|---------|--------|------|-----|------|---------|
{ALL_CRITICAL_RISKS_TABLE}
<!--
格式 (列出所有 Critical 风险，不限数量):
| 1 | VR-001 | JWT Token 未验证签名 | S | P01 | CWE-347 | 9.8 | 待修复 |
| 2 | VR-002 | SQL 注入漏洞 | T | DS01 | CWE-89 | 9.8 | 待修复 |
| 3 | VR-003 | 命令注入漏洞 | E | P03 | CWE-78 | 9.8 | 待修复 |
| ... | ... | ... | ... | ... | ... | ... | ... |

⚠️ 必须列出所有 Critical 风险，不限于 Top 5
-->

### 1.4 关键发现

{KEY_FINDINGS_SECTION}
<!--
格式:
#### 发现 1: {FINDING_TITLE}
- **威胁ID**: {THREAT_ID}
- **严重程度**: {SEVERITY}
- **影响**: {IMPACT_DESCRIPTION}
- **位置**: `{FILE_PATH}`
-->

### 1.5 立即行动建议

| 优先级 | 措施 | 目标威胁 | 风险降低 |
|--------|------|---------|---------|
| P0 | {P0_ACTION_1} | {P0_TARGET_1} | {P0_REDUCTION_1}% |
| P0 | {P0_ACTION_2} | {P0_TARGET_2} | {P0_REDUCTION_2}% |
| P1 | {P1_ACTION_1} | {P1_TARGET_1} | {P1_REDUCTION_1}% |

---

## 2. 系统架构概览

### 2.1 组件拓扑

```
{COMPONENT_TOPOLOGY_ASCII}
```
<!--
示例:
┌─────────────────────────────────────────────────────────────┐
│                        Internet                              │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer                             │
└─────────────────────────┬───────────────────────────────────┘
                          │
           ┌──────────────┼──────────────┐
           ▼              ▼              ▼
      ┌─────────┐    ┌─────────┐    ┌─────────┐
      │  Web UI │    │   API   │    │ Worker  │
      └────┬────┘    └────┬────┘    └────┬────┘
           │              │              │
           └──────────────┼──────────────┘
                          ▼
                   ┌─────────────┐
                   │  Database   │
                   └─────────────┘
-->

### 2.2 数据流图 (Level 1)

```
{DFD_ASCII}
```
<!--
示例:
                    ┌─────────┐
                    │   EI01  │
                    │  User   │
                    └────┬────┘
                         │ DF01: HTTP Request
                         ▼
   ┌─────────────────────────────────────────┐
   │              Trust Boundary              │
   │  ┌─────────┐    DF02     ┌─────────┐   │
   │  │   P01   │────────────→│   P02   │   │
   │  │ Frontend│             │   API   │   │
   │  └─────────┘             └────┬────┘   │
   │                               │ DF03   │
   │                               ▼        │
   │                         ┌─────────┐   │
   │                         │  DS01   │   │
   │                         │Database │   │
   │                         └─────────┘   │
   └─────────────────────────────────────────┘
-->

### 2.3 信任边界

| 边界ID | 边界名称 | 类型 | 包含元素 | 穿越数据流 |
|--------|---------|------|---------|-----------|
| {TB_ID_1} | {TB_NAME_1} | {TB_TYPE_1} | {TB_ELEMENTS_1} | {TB_FLOWS_1} |
| {TB_ID_2} | {TB_NAME_2} | {TB_TYPE_2} | {TB_ELEMENTS_2} | {TB_FLOWS_2} |

### 2.4 技术栈

| 层级 | 技术 | 版本 | 安全相关性 |
|------|-----|------|-----------|
| **语言** | {LANG} | {LANG_VER} | {LANG_SECURITY} |
| **框架** | {FRAMEWORK} | {FRAMEWORK_VER} | {FRAMEWORK_SECURITY} |
| **数据库** | {DATABASE} | {DB_VER} | {DB_SECURITY} |
| **认证** | {AUTH_TECH} | {AUTH_VER} | {AUTH_SECURITY} |

---

## 4. 安全功能设计评估 (Security Control Assessment)

### 4.1 评估矩阵 (9 安全域)

| 安全域 | 状态 | 发现数 | 关键问题 |
|--------|------|--------|---------|
| 1. 认证 (Authentication) | {AUTH_STATUS} | {AUTH_FINDINGS} | {AUTH_ISSUES} |
| 2. 授权 (Authorization) | {AUTHZ_STATUS} | {AUTHZ_FINDINGS} | {AUTHZ_ISSUES} |
| 3. 输入验证 | {INPUT_STATUS} | {INPUT_FINDINGS} | {INPUT_ISSUES} |
| 4. 输出编码 | {OUTPUT_STATUS} | {OUTPUT_FINDINGS} | {OUTPUT_ISSUES} |
| 5. 加密 (Cryptography) | {CRYPTO_STATUS} | {CRYPTO_FINDINGS} | {CRYPTO_ISSUES} |
| 6. 密钥管理 | {KEY_STATUS} | {KEY_FINDINGS} | {KEY_ISSUES} |
| 7. 错误处理 | {ERROR_STATUS} | {ERROR_FINDINGS} | {ERROR_ISSUES} |
| 8. 日志审计 | {LOG_STATUS} | {LOG_FINDINGS} | {LOG_ISSUES} |
| 9. 通信安全 | {COMM_STATUS} | {COMM_FINDINGS} | {COMM_ISSUES} |

**状态说明**: ✅ 已实现 | ⚠️ 部分实现 | ❌ 缺失 | ➖ 不适用

### 4.2 关键安全发现详情

{SECURITY_DESIGN_FINDINGS_SECTION}
<!--
格式:
#### SF-P4-{SEQ}: {FINDING_TITLE}
- **安全域**: {DOMAIN}
- **发现类型**: {TYPE}
- **当前状态**: {CURRENT_STATE}
- **推荐改进**: {RECOMMENDATION}
-->

### 4.3 详细文档参考

> 📄 **完整安全功能设计评估详情请参见阶段文档**:
> - 📁 `P2-DFD-ANALYSIS.md` — 数据流图分析、数据流转路径、关键模块识别
> - 📁 `P3-TRUST-BOUNDARY.md` — 信任边界划分、安全域定义、边界穿越分析
> - 📁 `P4-SECURITY-DESIGN-REVIEW.md` — 9大安全域评估详情、认证/授权/加密等安全功能实现分析

---

## 3. STRIDE 威胁分析 (Threat Summary)

### 3.1 威胁汇总表

| 威胁ID | STRIDE | 元素 | 威胁名称 | CWE | CVSS | 严重程度 | 状态 |
|--------|--------|------|---------|-----|------|---------|------|
{THREAT_SUMMARY_TABLE}
<!--
格式:
| T-S-P01-001 | S | P01 | JWT Token 伪造 | CWE-347 | 8.8 | 🔴 Critical | 待修复 |
| T-T-DS01-001 | T | DS01 | SQL 注入 | CWE-89 | 9.8 | 🔴 Critical | 待修复 |
-->

### 3.2 Spoofing (欺骗) 威胁

| 威胁ID | 元素 | 威胁名称 | CWE | CVSS | 严重程度 |
|--------|------|---------|-----|------|---------|
{SPOOFING_THREATS_TABLE}

### 3.3 Tampering (篡改) 威胁

| 威胁ID | 元素 | 威胁名称 | CWE | CVSS | 严重程度 |
|--------|------|---------|-----|------|---------|
{TAMPERING_THREATS_TABLE}

### 3.4 Repudiation (抵赖) 威胁

| 威胁ID | 元素 | 威胁名称 | CWE | CVSS | 严重程度 |
|--------|------|---------|-----|------|---------|
{REPUDIATION_THREATS_TABLE}

### 3.5 Information Disclosure (信息泄露) 威胁

| 威胁ID | 元素 | 威胁名称 | CWE | CVSS | 严重程度 |
|--------|------|---------|-----|------|---------|
{INFO_DISCLOSURE_THREATS_TABLE}

### 3.6 Denial of Service (拒绝服务) 威胁

| 威胁ID | 元素 | 威胁名称 | CWE | CVSS | 严重程度 |
|--------|------|---------|-----|------|---------|
{DOS_THREATS_TABLE}

### 3.7 Elevation of Privilege (权限提升) 威胁

| 威胁ID | 元素 | 威胁名称 | CWE | CVSS | 严重程度 |
|--------|------|---------|-----|------|---------|
{EOP_THREATS_TABLE}

### 3.8 威胁详细分析

{THREAT_DETAILS_SECTION}
<!--
使用 risk-detail.schema.md 定义的完整格式
每个 Critical/High 威胁一个完整详情块
-->

### 3.9 详细文档参考

> 📄 **完整威胁分析详情请参见阶段文档**:
> - 📁 `P5-STRIDE-THREATS.md` — 包含完整的 STRIDE 威胁识别过程、威胁枚举、CWE/CAPEC 映射详情

---

## 5. 风险验证与POC设计 (Critical Vulnerabilities)

> ⚡ **本章节基于 Phase 6 风险验证工作流输出**

### 5.1 POC 验证方法论

#### 验证状态说明

| 状态标识 | 含义 | 判定标准 |
|---------|------|---------|
| ✅ **已验证** | POC 执行成功，漏洞真实可利用 | 成功复现攻击行为并获得预期结果 |
| ⚠️ **需验证** | 理论可行但需手动验证 | 需要特定环境或权限才能验证 |
| 📋 **理论可行** | 基于代码分析推导，未执行 | 代码路径存在但未实际测试 |
| ❌ **已排除** | 验证后确认不可利用 | 存在缓解措施或条件不满足 |

#### 验证覆盖统计

| 威胁级别 | 已识别 | 已验证 | 待验证 | 已排除 | 验证率 |
|---------|--------|--------|--------|--------|--------|
| 🔴 Critical | {CRITICAL_IDENTIFIED} | {CRITICAL_VERIFIED} | {CRITICAL_PENDING} | {CRITICAL_EXCLUDED} | {CRITICAL_RATE}% |
| 🟠 High | {HIGH_IDENTIFIED} | {HIGH_VERIFIED} | {HIGH_PENDING} | {HIGH_EXCLUDED} | {HIGH_RATE}% |
| 🟡 Medium | {MEDIUM_IDENTIFIED} | {MEDIUM_VERIFIED} | {MEDIUM_PENDING} | {MEDIUM_EXCLUDED} | {MEDIUM_RATE}% |
| **总计** | {TOTAL_IDENTIFIED} | {TOTAL_VERIFIED} | {TOTAL_PENDING} | {TOTAL_EXCLUDED} | {TOTAL_RATE}% |

### 5.2 POC 验证详情

{POC_DETAILS_SECTION}
<!--
每个 Critical/High 威胁一个 POC 块，格式如下:

#### POC-{SEQ}: {POC_TITLE}

| 属性 | 值 |
|------|-----|
| **关联威胁** | {THREAT_ID} |
| **威胁类型** | {STRIDE_TYPE} |
| **验证状态** | {VERIFICATION_STATUS} |
| **利用难度** | {EXPLOITATION_DIFFICULTY} |
| **前置条件** | {PREREQUISITES} |

**漏洞位置**:
```
文件: {FILE_PATH}
函数: {FUNCTION_NAME}
行号: {LINE_NUMBER}
```

**漏洞代码片段**:
```{LANGUAGE}
{VULNERABLE_CODE_SNIPPET}
```

**利用步骤**:
1. {STEP_1}
2. {STEP_2}
3. {STEP_3}

**POC 代码**:
```{LANGUAGE}
{POC_CODE}
```

**预期结果**:
```
{EXPECTED_OUTPUT}
```

**验证截图/日志** (如有):
```
{VERIFICATION_LOG}
```

**风险评估**:
- 利用复杂度: {COMPLEXITY}
- 攻击向量: {ATTACK_VECTOR}
- 影响范围: {IMPACT_SCOPE}
- 数据敏感性: {DATA_SENSITIVITY}
-->

### 5.3 POC 汇总表

| POC-ID | 威胁ID | 漏洞名称 | 验证状态 | 利用难度 | CVSS | 优先级 |
|--------|--------|---------|---------|---------|------|--------|
{POC_SUMMARY_TABLE}
<!--
格式:
| POC-001 | T-S-P01-001 | JWT Token 伪造 | ✅ 已验证 | 中 | 8.8 | P0 |
| POC-002 | T-T-DS01-001 | SQL 注入 | ✅ 已验证 | 低 | 9.8 | P0 |
| POC-003 | T-I-P02-001 | 敏感信息泄露 | ⚠️ 需验证 | 低 | 7.5 | P1 |
-->

### 5.4 详细文档参考

> 📄 **完整风险验证与POC设计详情请参见阶段文档**:
> - 📁 `P6-RISK-VALIDATION.md` — 包含完整的风险验证过程、POC代码详情、验证结果记录、攻击路径可行性分析

---

## 6. 攻击路径分析

> ⚡ **本章节展示高危威胁的完整攻击链和利用路径**

### 6.1 攻击路径可行性矩阵

| 攻击路径 | 入口点 | 关键节点 | 最终目标 | 可行性评分 | 检测难度 | 优先修复 |
|---------|--------|---------|---------|-----------|---------|---------|
{ATTACK_PATH_MATRIX}
<!--
格式:
| AP-001: 认证绕过→数据库访问 | API Gateway | Auth Service | 数据库 | 8.5/10 | 低 | ✅ |
| AP-002: 配置注入→代码执行 | 配置文件 | Worker | 服务器 | 7.0/10 | 中 | ✅ |
| AP-003: 信息泄露→权限提升 | 错误页面 | API | 管理后台 | 6.5/10 | 高 | ⚠️ |
-->

### 6.2 攻击链详细分析

{ATTACK_CHAIN_DETAILS_SECTION}
<!--
每条高危攻击链一个详细分析块，格式如下:

#### 攻击链 {SEQ}: {ATTACK_CHAIN_TITLE}

**攻击链概要**:

| 属性 | 值 |
|------|-----|
| **起始点** | {ENTRY_POINT} |
| **攻击目标** | {TARGET} |
| **影响范围** | {IMPACT_SCOPE} |
| **利用难度** | {DIFFICULTY} |
| **关联威胁** | {RELATED_THREATS} |

**攻击流程图**:
```
┌─────────────────────────────────────────────────────────────────┐
│                     攻击链: {ATTACK_CHAIN_NAME}                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 1: {STEP1_TITLE}                                          │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  攻击者 ──→ {TARGET1}                                     │   │
│  │  动作: {ACTION1}                                          │   │
│  │  代码位置: {CODE_LOC1}                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  Step 2: {STEP2_TITLE}                                          │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  {SOURCE2} ──→ {TARGET2}                                  │   │
│  │  动作: {ACTION2}                                          │   │
│  │  代码位置: {CODE_LOC2}                                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  Step N: {STEPN_TITLE}                                          │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  结果: {FINAL_RESULT}                                     │   │
│  │  影响: {FINAL_IMPACT}                                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**步骤分解**:

| 步骤 | 攻击动作 | 利用漏洞 | 数据/权限变化 |
|------|---------|---------|--------------|
| 1 | {ACTION_1} | {VULN_1} | {CHANGE_1} |
| 2 | {ACTION_2} | {VULN_2} | {CHANGE_2} |
| N | {ACTION_N} | {VULN_N} | {CHANGE_N} |

**前置条件**:
1. {PREREQ_1}
2. {PREREQ_2}

**利用代码/命令**:
```{LANGUAGE}
{EXPLOITATION_CODE}
```

**检测指标 (IOC)**:
- {IOC_1}
- {IOC_2}

**防御建议**:
1. **切断点 1**: {DEFENSE_1}
2. **切断点 2**: {DEFENSE_2}
-->

### 6.3 攻击面热力图

```
{ATTACK_SURFACE_HEATMAP_ASCII}
```
<!--
示例:
┌─────────────────────────────────────────────────────────────────┐
│                        攻击面热力分析                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  组件名称          威胁数   攻击路径   风险评分   热力等级       │
│  ─────────────────────────────────────────────────────────────  │
│  API Gateway         12        4        9.2      ████████████   │
│  Auth Service         8        3        8.5      ██████████     │
│  Database             6        2        7.8      ████████       │
│  File Storage         5        2        7.0      ███████        │
│  Worker Service       3        1        5.5      █████          │
│  Frontend             2        1        4.0      ████           │
│                                                                  │
│  图例: █ = 1.0 风险单位                                          │
│  ████████████ = Critical (9.0+)                                 │
│  ██████████   = High (7.0-8.9)                                  │
│  ████████     = Medium (5.0-6.9)                                │
│  █████        = Low (< 5.0)                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
-->

### 6.4 攻击路径优先级排序

| 优先级 | 攻击路径 | 风险评分 | 修复建议 | 预计工作量 |
|--------|---------|---------|---------|-----------|
| P0 | {AP_P0_1} | {SCORE_P0_1} | {FIX_P0_1} | {EFFORT_P0_1} |
| P0 | {AP_P0_2} | {SCORE_P0_2} | {FIX_P0_2} | {EFFORT_P0_2} |
| P1 | {AP_P1_1} | {SCORE_P1_1} | {FIX_P1_1} | {EFFORT_P1_1} |
| P2 | {AP_P2_1} | {SCORE_P2_1} | {FIX_P2_1} | {EFFORT_P2_1} |

---

## 7. 威胁优先级矩阵

### 7.1 风险评估矩阵

```
              ┌─────────────────────────────────────────────────┐
    影响      │                    可利用性                      │
              │  Very High     High        Medium      Low      │
   ──────────┼─────────────────────────────────────────────────┤
   Critical  │  🔴 P0        🔴 P0       🟠 P1      🟠 P1      │
   High      │  🔴 P0        🟠 P1       🟠 P1      🟡 P2      │
   Medium    │  🟠 P1        🟠 P1       🟡 P2      🟡 P2      │
   Low       │  🟡 P2        🟡 P2       🟢 P3      🟢 P3      │
              └─────────────────────────────────────────────────┘
```

### 7.2 威胁分布矩阵

{THREAT_DISTRIBUTION_MATRIX}
<!--
按上述矩阵格式展示每个威胁的分布位置
-->

### 7.3 攻击面热力图

```
{ATTACK_SURFACE_HEATMAP}
```
<!--
示例:
组件          威胁数  Critical  High   Medium   Low    风险等级
─────────────────────────────────────────────────────────────
API Gateway     12      3        5       3       1     ████████ Critical
Auth Service     8      2        3       2       1     ██████   High
Database         6      1        2       2       1     █████    High
Frontend         4      0        1       2       1     ███      Medium
Worker           2      0        0       1       1     ██       Low
-->

---

## 8. 缓解措施建议

### 8.1 P0 - 立即修复

{P0_MITIGATIONS_SECTION}
<!--
格式:
#### M-001: {MITIGATION_TITLE}
**针对威胁**: {THREAT_IDS}
**风险降低**: {RISK_REDUCTION}%

**当前状态**:
{CURRENT_STATE}

**推荐控制**:
{RECOMMENDED_CONTROL}

```{LANGUAGE}
// 实现代码示例
{CODE_EXAMPLE}
```
-->

### 8.2 P1 - 紧急

{P1_MITIGATIONS_SECTION}

### 8.3 P2 - 高优先级

{P2_MITIGATIONS_SECTION}

### 8.4 实施路线图

| 阶段 | 措施 | 优先级 | 依赖 | 风险降低 |
|------|------|--------|------|---------|
| 阶段 1 | {PHASE1_MEASURES} | P0 | 无 | {PHASE1_REDUCTION}% |
| 阶段 2 | {PHASE2_MEASURES} | P1 | 阶段 1 | {PHASE2_REDUCTION}% |
| 阶段 3 | {PHASE3_MEASURES} | P2 | 阶段 2 | {PHASE3_REDUCTION}% |

**防御纵深架构**:

```
{DEFENSE_IN_DEPTH_ASCII}
```

---

## 9. 合规性映射

### 9.1 OWASP Top 10 (2021) 映射

| OWASP | 名称 | 相关威胁 | 状态 |
|-------|------|---------|------|
| A01 | Broken Access Control | {A01_THREATS} | {A01_STATUS} |
| A02 | Cryptographic Failures | {A02_THREATS} | {A02_STATUS} |
| A03 | Injection | {A03_THREATS} | {A03_STATUS} |
| A04 | Insecure Design | {A04_THREATS} | {A04_STATUS} |
| A05 | Security Misconfiguration | {A05_THREATS} | {A05_STATUS} |
| A06 | Vulnerable Components | {A06_THREATS} | {A06_STATUS} |
| A07 | Auth Failures | {A07_THREATS} | {A07_STATUS} |
| A08 | Data Integrity Failures | {A08_THREATS} | {A08_STATUS} |
| A09 | Logging Failures | {A09_THREATS} | {A09_STATUS} |
| A10 | SSRF | {A10_THREATS} | {A10_STATUS} |

### 9.2 OWASP LLM Top 10 映射

<!-- 仅当项目包含 AI/LLM 组件时生成 -->
{OWASP_LLM_MAPPING_SECTION}

---

## 附录

### 附录 A: DFD 元素完整清单

#### A.1 进程 (Processes)

| ID | 名称 | 描述 | 威胁数 |
|----|------|------|--------|
{PROCESSES_TABLE}

#### A.2 数据存储 (Data Stores)

| ID | 名称 | 描述 | 敏感数据 | 威胁数 |
|----|------|------|---------|--------|
{DATA_STORES_TABLE}

#### A.3 数据流 (Data Flows)

| ID | 源 | 目标 | 协议 | 加密 | 威胁数 |
|----|-----|------|------|------|--------|
{DATA_FLOWS_TABLE}

#### A.4 外部实体 (External Entities)

| ID | 名称 | 类型 | 描述 |
|----|------|------|------|
{EXTERNAL_ENTITIES_TABLE}

### 附录 B: Mermaid DFD 源码

```mermaid
{MERMAID_DFD_SOURCE}
```

### 附录 C: 威胁完整清单

{FULL_THREAT_LIST}
<!--
所有威胁的简化列表，包含 ID、名称、CWE、严重程度、状态
-->

### 附录 D: 知识库查询记录

| 查询类型 | 查询参数 | 结果 | 使用位置 |
|---------|---------|------|---------|
{KB_QUERIES_TABLE}

### 附录 E: 参考资料

1. Microsoft STRIDE Threat Modeling
2. OWASP Top 10 2021
3. CWE/SANS Top 25
4. MITRE ATT&CK Framework
5. {ADDITIONAL_REFERENCES}

---

**报告结束**

---

> **免责声明**: 本风险评估报告基于提供的代码和信息进行自动化分析生成。
> 实际安全风险可能因运行环境、配置和使用方式而异。
> 建议结合渗透测试和安全审计进行综合评估。
