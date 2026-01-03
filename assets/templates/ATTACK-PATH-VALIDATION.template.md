<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

# 攻击路径验证报告: {PROJECT_NAME}

> **评估时间**: {ASSESSMENT_DATETIME}
> **分析师**: Claude (STRIDE Deep Threat Modeling)
> **框架版本**: STRIDE-TM v1.0.2
> **报告版本**: {REPORT_VERSION}
> **分类**: 机密 - 安全评估

---

## 1. 验证概述

### 1.1 验证范围

| 属性 | 值 |
|------|-----|
| **评估目标** | {PROJECT_NAME} |
| **验证威胁数** | {VALIDATED_THREATS} |
| **确认攻击路径** | {CONFIRMED_PATHS} |
| **排除误报** | {FALSE_POSITIVES} |
| **验证方法** | 代码审计 + POC验证 |

### 1.2 验证方法

| 方法 | 描述 | 使用场景 |
|------|------|---------|
| **代码审计** | 静态代码分析确认漏洞存在 | 所有威胁 |
| **POC验证** | 构造验证请求/代码 | Critical/High威胁 |
| **攻击链分析** | 分析多步骤攻击路径 | 复杂攻击场景 |
| **影响评估** | 评估实际可利用性和影响 | 风险评级校准 |

### 1.3 结果摘要

| 验证结果 | 数量 | 百分比 |
|---------|------|--------|
| ✅ 已确认 (Confirmed) | {CONFIRMED_COUNT} | {CONFIRMED_PCT}% |
| ⚠️ 需进一步验证 | {NEEDS_VERIFICATION} | {NEEDS_PCT}% |
| ❌ 误报 (False Positive) | {FP_COUNT} | {FP_PCT}% |
| **总计** | **{TOTAL_VALIDATED}** | **100%** |

---

## 2. 已验证攻击路径

### 2.1 攻击路径汇总

| 路径ID | 目标威胁 | 攻击链描述 | 可利用性 | 验证状态 |
|--------|---------|-----------|---------|---------|
{ATTACK_PATHS_SUMMARY_TABLE}
<!--
格式:
| AP-001 | T-S-P01-001 | JWT伪造 → 身份冒充 | Very High | ✅ 已确认 |
| AP-002 | T-T-DS01-001 | SQL注入 → 数据泄露 | High | ✅ 已确认 |
| AP-003 | T-E-P02-001 | 权限绕过 → 管理员访问 | High | ✅ 已确认 |
-->

### 2.2 攻击路径详情

{ATTACK_PATH_DETAILS_SECTION}

<!--
=============================================================================
攻击路径详情模板
=============================================================================

#### AP-{SEQ}: {ATTACK_PATH_NAME}

**目标威胁**: {THREAT_ID} - {THREAT_NAME}

**严重程度**: {SEVERITY_ICON} {SEVERITY}

**CVSS评分**: {CVSS_SCORE}

**攻击链可视化**:

```
{ATTACK_CHAIN_ASCII}
```

示例:
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   攻击者    │     │   入口点    │     │   中间步骤   │     │   最终影响  │
│             │────►│             │────►│             │────►│             │
│  External   │     │ Login API   │     │ JWT Decode  │     │ Admin Access│
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
        │                 │                   │                   │
        │                 │                   │                   │
    攻击者获取        分析JWT            破解弱密钥          冒充管理员
    有效JWT样本      结构和算法         伪造Token          执行任意操作
```

**攻击链描述**:

| 步骤 | 描述 | 所需技能 | 所需工具 |
|------|------|---------|---------|
| 1 | {STEP_1_DESC} | {STEP_1_SKILL} | {STEP_1_TOOL} |
| 2 | {STEP_2_DESC} | {STEP_2_SKILL} | {STEP_2_TOOL} |
| 3 | {STEP_3_DESC} | {STEP_3_SKILL} | {STEP_3_TOOL} |
| 4 | {STEP_4_DESC} | {STEP_4_SKILL} | {STEP_4_TOOL} |

**前置条件**:

1. {PREREQUISITE_1}
2. {PREREQUISITE_2}
3. {PREREQUISITE_3}

**验证步骤**:

```{VERIFICATION_LANGUAGE}
{VERIFICATION_STEPS}
```

**POC 方法**:

**类型**: {POC_TYPE}

**描述**: {POC_DESCRIPTION}

```{POC_LANGUAGE}
{POC_CODE}
```

**验证命令**:

```bash
{VERIFICATION_COMMAND}
```

**预期结果**: {EXPECTED_RESULT}

**实际结果**: {ACTUAL_RESULT}

**可利用性评估**:

| 因素 | 评估 | 说明 |
|------|------|------|
| 攻击复杂度 | {ATTACK_COMPLEXITY} | {AC_DESC} |
| 所需权限 | {REQUIRED_PRIVILEGES} | {RP_DESC} |
| 用户交互 | {USER_INTERACTION} | {UI_DESC} |
| 影响范围 | {SCOPE} | {SCOPE_DESC} |

**ATT&CK 映射**:

| 战术 | 技术 | 子技术 |
|------|------|--------|
| {TACTIC_1} | {TECHNIQUE_1} | {SUB_TECHNIQUE_1} |
| {TACTIC_2} | {TECHNIQUE_2} | {SUB_TECHNIQUE_2} |

**影响分析**:

- **机密性影响**: {IMPACT_C} - {IMPACT_C_DESC}
- **完整性影响**: {IMPACT_I} - {IMPACT_I_DESC}
- **可用性影响**: {IMPACT_A} - {IMPACT_A_DESC}

**建议缓解**:

| 缓解措施 | 描述 | 参考 |
|---------|------|------|
| {MITIGATION_1} | {MIT_DESC_1} | M-{XXX} |
| {MITIGATION_2} | {MIT_DESC_2} | M-{XXX} |

---

-->

---

## 3. 攻击面分析

### 3.1 外部攻击面

```
{EXTERNAL_ATTACK_SURFACE_ASCII}
```
<!--
示例:
┌─────────────────────────────────────────────────────────────────────────────┐
│                         External Attack Surface                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐                                                            │
│  │  Internet   │                                                            │
│  └──────┬──────┘                                                            │
│         │                                                                    │
│  ═══════╪════════════════════════════════════════════════════════════════   │
│         │         Network Boundary                                           │
│  ═══════╪════════════════════════════════════════════════════════════════   │
│         │                                                                    │
│         ▼                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      External Entry Points                           │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                      │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐        │   │
│  │  │ HTTPS:443 │  │ API:8080  │  │ WSS:3000  │  │ Webhook   │        │   │
│  │  │ (Web UI)  │  │ (REST)    │  │ (Socket)  │  │ (Inbound) │        │   │
│  │  │  ████████ │  │  ██████   │  │  ████     │  │  ██       │        │   │
│  │  │ 12 threats│  │ 8 threats │  │ 4 threats │  │ 2 threats │        │   │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘        │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Risk Level: ████████ Critical  ██████ High  ████ Medium  ██ Low           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
-->

| 入口点 | 端口/协议 | 威胁数 | 最高风险 | 验证状态 |
|--------|----------|--------|---------|---------|
{EXTERNAL_ENTRY_POINTS_TABLE}

### 3.2 内部攻击面

```
{INTERNAL_ATTACK_SURFACE_ASCII}
```

| 内部接口 | 类型 | 威胁数 | 最高风险 | 验证状态 |
|---------|------|--------|---------|---------|
{INTERNAL_ENTRY_POINTS_TABLE}

### 3.3 高风险入口点

| 排名 | 入口点 | 威胁数 | Critical | High | 累计风险 |
|------|--------|--------|----------|------|---------|
{HIGH_RISK_ENTRY_POINTS_TABLE}
<!--
格式:
| 1 | API Gateway (/api/v1/*) | 12 | 3 | 5 | 85% |
| 2 | Auth Endpoint (/auth/*) | 8 | 2 | 3 | 70% |
| 3 | WebSocket (/ws) | 4 | 1 | 2 | 50% |
-->

---

## 4. 攻击链可视化

### 4.1 完整攻击链图

```
{FULL_ATTACK_CHAIN_DIAGRAM}
```
<!--
示例:
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Attack Chain Overview                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Initial Access          Execution           Persistence         Impact     │
│  ─────────────          ──────────          ───────────          ──────     │
│                                                                              │
│  ┌───────────┐         ┌───────────┐       ┌───────────┐     ┌───────────┐ │
│  │ AP-001    │────────►│ AP-002    │──────►│ AP-003    │────►│ AP-004    │ │
│  │JWT Bypass │         │Code Exec  │       │ Backdoor  │     │Data Theft │ │
│  └───────────┘         └───────────┘       └───────────┘     └───────────┘ │
│       │                                                                      │
│       │                ┌───────────┐                        ┌───────────┐  │
│       └───────────────►│ AP-005    │───────────────────────►│ AP-006    │  │
│                        │SQL Inject │                        │ Privilege │  │
│                        └───────────┘                        └───────────┘  │
│                                                                              │
│  Legend: ───► Leads to   ════ Critical Path                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
-->

### 4.2 关键攻击链

| 攻击链 | 路径 | 最终影响 | 风险等级 |
|--------|------|---------|---------|
{CRITICAL_ATTACK_CHAINS_TABLE}
<!--
格式:
| Chain-1 | AP-001 → AP-002 → AP-004 | 完整数据泄露 | 🔴 Critical |
| Chain-2 | AP-005 → AP-006 | 权限提升至管理员 | 🔴 Critical |
| Chain-3 | AP-001 → AP-003 | 持久化后门 | 🟠 High |
-->

---

## 5. 排除项

### 5.1 排除的误报

| 威胁ID | 原始风险名称 | 排除原因 | 验证证据 |
|--------|-------------|---------|---------|
{FALSE_POSITIVES_TABLE}
<!--
格式:
| T-S-P01-003 | 会话固定 | 实际使用随机Session ID | 代码审计确认 |
| T-T-DS01-002 | 时间盲注 | 查询使用参数化 | POC验证失败 |
-->

### 5.2 需进一步验证

| 威胁ID | 风险名称 | 当前状态 | 所需验证 |
|--------|---------|---------|---------|
{NEEDS_VERIFICATION_TABLE}
<!--
格式:
| T-I-P02-001 | 敏感日志 | 需确认生产配置 | 检查生产日志级别 |
| T-D-P01-002 | 资源耗尽 | 需负载测试 | 压力测试验证 |
-->

---

## 6. 验证证据

### 6.1 代码审计发现

| 威胁ID | 文件位置 | 问题代码 | 验证结论 |
|--------|---------|---------|---------|
{CODE_AUDIT_EVIDENCE_TABLE}

### 6.2 POC 执行记录

| 攻击路径 | POC类型 | 执行时间 | 结果 |
|---------|--------|---------|------|
{POC_EXECUTION_LOG}

---

## 7. 风险评级校准

### 7.1 验证后风险调整

| 威胁ID | 原始评级 | 调整后评级 | 调整原因 |
|--------|---------|-----------|---------|
{RISK_ADJUSTMENT_TABLE}
<!--
格式:
| T-S-P01-001 | High | Critical | POC确认可远程利用 |
| T-T-DS01-001 | Critical | High | 需要认证后才能利用 |
| T-I-P02-001 | Medium | Low | 信息敏感度低于预期 |
-->

### 7.2 验证后统计

| 严重程度 | 原始数量 | 验证后数量 | 变化 |
|---------|---------|-----------|------|
| 🔴 Critical | {ORIG_CRITICAL} | {NEW_CRITICAL} | {CRITICAL_CHANGE} |
| 🟠 High | {ORIG_HIGH} | {NEW_HIGH} | {HIGH_CHANGE} |
| 🟡 Medium | {ORIG_MEDIUM} | {NEW_MEDIUM} | {MEDIUM_CHANGE} |
| 🟢 Low | {ORIG_LOW} | {NEW_LOW} | {LOW_CHANGE} |

---

## 附录

### 附录 A: 验证工具清单

| 工具 | 版本 | 用途 |
|------|------|------|
| curl | latest | HTTP 请求测试 |
| jwt-tool | 2.x | JWT 分析和测试 |
| sqlmap | 1.x | SQL 注入验证 |
| Burp Suite | 2023.x | 综合 Web 安全测试 |
| {ADDITIONAL_TOOLS} | | |

### 附录 B: 验证环境

| 环境 | 配置 | 说明 |
|------|------|------|
| 测试环境 | {TEST_ENV_CONFIG} | 用于POC验证 |
| 代码分析 | {ANALYSIS_CONFIG} | 静态代码审计 |

### 附录 C: 验证时间线

| 日期时间 | 活动 | 发现 |
|---------|------|------|
{VALIDATION_TIMELINE}

---

**报告结束**

---

> **安全声明**: 本报告包含敏感安全信息，包括可利用的漏洞详情和POC代码。
> 请严格限制访问范围，仅供授权安全人员使用。
> 未经授权禁止传播或用于非法目的。
