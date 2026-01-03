<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

# 合规性报告: {PROJECT_NAME}

> **评估时间**: {ASSESSMENT_DATETIME}
> **分析师**: Claude (Deep Risk Analysis)
> **框架版本**: STRIDE-TM v1.0.2
> **报告版本**: {REPORT_VERSION}

---

## 1. 合规概述

### 1.1 适用合规框架

| 框架 | 版本 | 适用原因 | 评估范围 |
|------|------|---------|---------|
| OWASP Top 10 | 2021 | Web 应用安全标准 | 全部 |
| OWASP LLM Top 10 | 2023 | AI/LLM 安全 (如适用) | {LLM_SCOPE} |
| CWE/SANS Top 25 | 2023 | 危险软件漏洞 | 全部 |
| NIST CSF | 2.0 | 网络安全框架 | {NIST_SCOPE} |
| ISO 27001 | 2022 | 信息安全管理 | {ISO_SCOPE} |
| PCI-DSS | 4.0 | 支付卡数据安全 | {PCI_SCOPE} |

### 1.2 合规差距摘要

| 框架 | 相关控制 | 符合 | 部分符合 | 不符合 | 符合率 |
|------|---------|------|---------|--------|-------|
| OWASP Top 10 | {OWASP_TOTAL} | {OWASP_PASS} | {OWASP_PARTIAL} | {OWASP_FAIL} | {OWASP_RATE}% |
| CWE Top 25 | {CWE_TOTAL} | {CWE_PASS} | {CWE_PARTIAL} | {CWE_FAIL} | {CWE_RATE}% |
| NIST CSF | {NIST_TOTAL} | {NIST_PASS} | {NIST_PARTIAL} | {NIST_FAIL} | {NIST_RATE}% |
| ISO 27001 | {ISO_TOTAL} | {ISO_PASS} | {ISO_PARTIAL} | {ISO_FAIL} | {ISO_RATE}% |

### 1.3 合规状态总览

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Compliance Status Overview                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  OWASP Top 10:                                                               │
│  ████████████████████████░░░░░░░░░░░░░░░░ {OWASP_RATE}% 符合                 │
│                                                                              │
│  CWE Top 25:                                                                 │
│  ██████████████████████████████░░░░░░░░░░ {CWE_RATE}% 符合                   │
│                                                                              │
│  NIST CSF:                                                                   │
│  ████████████████████████████████████░░░░ {NIST_RATE}% 符合                  │
│                                                                              │
│  ISO 27001:                                                                  │
│  ██████████████████████████████████████░░ {ISO_RATE}% 符合                   │
│                                                                              │
│  图例: ████ 符合  ░░░░ 差距                                                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. OWASP Top 10 (2021) 映射

### 2.1 映射总览

| # | OWASP | 名称 | 相关威胁 | 状态 | 差距说明 |
|---|-------|------|---------|------|---------|
| A01 | Broken Access Control | 失效的访问控制 | {A01_THREATS} | {A01_STATUS} | {A01_GAP} |
| A02 | Cryptographic Failures | 加密机制失效 | {A02_THREATS} | {A02_STATUS} | {A02_GAP} |
| A03 | Injection | 注入 | {A03_THREATS} | {A03_STATUS} | {A03_GAP} |
| A04 | Insecure Design | 不安全设计 | {A04_THREATS} | {A04_STATUS} | {A04_GAP} |
| A05 | Security Misconfiguration | 安全配置错误 | {A05_THREATS} | {A05_STATUS} | {A05_GAP} |
| A06 | Vulnerable Components | 易受攻击的组件 | {A06_THREATS} | {A06_STATUS} | {A06_GAP} |
| A07 | Auth Failures | 身份认证失效 | {A07_THREATS} | {A07_STATUS} | {A07_GAP} |
| A08 | Data Integrity Failures | 软件和数据完整性失效 | {A08_THREATS} | {A08_STATUS} | {A08_GAP} |
| A09 | Logging Failures | 安全日志和监控失效 | {A09_THREATS} | {A09_STATUS} | {A09_GAP} |
| A10 | SSRF | 服务器端请求伪造 | {A10_THREATS} | {A10_STATUS} | {A10_GAP} |

**状态说明**: ✅ 符合 | ⚠️ 部分符合 | ❌ 不符合 | ➖ 不适用

### 2.2 详细分析

{OWASP_DETAILED_ANALYSIS}
<!--
格式:

#### A01: Broken Access Control (失效的访问控制)

**相关威胁**:
| 威胁ID | 风险名称 | 严重程度 |
|--------|---------|---------|
| T-E-P01-001 | 水平越权访问 | 🔴 Critical |
| T-E-P02-002 | 垂直越权访问 | 🟠 High |

**当前状态**: ⚠️ 部分符合

**发现问题**:
1. {ISSUE_1}
2. {ISSUE_2}

**建议措施**:
1. {MEASURE_1}
2. {MEASURE_2}

**参考缓解**: M-016 (RBAC Enhancement)

---
-->

---

## 3. OWASP LLM Top 10 映射

<!-- 仅当项目包含 AI/LLM 组件时生成此章节 -->

{LLM_SECTION_CONDITION}

### 3.1 映射总览

| # | LLM | 名称 | 相关威胁 | 状态 | 差距说明 |
|---|-----|------|---------|------|---------|
| LLM01 | Prompt Injection | 提示注入 | {LLM01_THREATS} | {LLM01_STATUS} | {LLM01_GAP} |
| LLM02 | Insecure Output | 不安全输出处理 | {LLM02_THREATS} | {LLM02_STATUS} | {LLM02_GAP} |
| LLM03 | Training Data Poisoning | 训练数据投毒 | {LLM03_THREATS} | {LLM03_STATUS} | {LLM03_GAP} |
| LLM04 | Model DoS | 模型拒绝服务 | {LLM04_THREATS} | {LLM04_STATUS} | {LLM04_GAP} |
| LLM05 | Supply Chain | 供应链漏洞 | {LLM05_THREATS} | {LLM05_STATUS} | {LLM05_GAP} |
| LLM06 | Sensitive Info | 敏感信息泄露 | {LLM06_THREATS} | {LLM06_STATUS} | {LLM06_GAP} |
| LLM07 | Insecure Plugin | 不安全插件设计 | {LLM07_THREATS} | {LLM07_STATUS} | {LLM07_GAP} |
| LLM08 | Excessive Agency | 过度代理 | {LLM08_THREATS} | {LLM08_STATUS} | {LLM08_GAP} |
| LLM09 | Overreliance | 过度依赖 | {LLM09_THREATS} | {LLM09_STATUS} | {LLM09_GAP} |
| LLM10 | Model Theft | 模型窃取 | {LLM10_THREATS} | {LLM10_STATUS} | {LLM10_GAP} |

### 3.2 详细分析

{LLM_DETAILED_ANALYSIS}

---

## 4. CWE 映射

### 4.1 按 CWE 分组的风险清单

| CWE | 名称 | 威胁数 | 最高严重程度 | 相关威胁 |
|-----|------|--------|-------------|---------|
{CWE_GROUPED_TABLE}
<!--
格式:
| CWE-89 | SQL注入 | 3 | 🔴 Critical | T-T-DS01-001, T-I-DS01-002 |
| CWE-79 | XSS | 2 | 🟠 High | T-T-P01-003, T-I-P01-004 |
| CWE-352 | CSRF | 1 | 🟡 Medium | T-T-P01-005 |
-->

### 4.2 CWE Top 25 覆盖

| 排名 | CWE | 名称 | 是否涉及 | 相关威胁 |
|------|-----|------|---------|---------|
{CWE_TOP25_TABLE}
<!--
格式:
| 1 | CWE-787 | 越界写入 | 否 | - |
| 2 | CWE-79 | XSS | 是 | T-T-P01-003 |
| 3 | CWE-89 | SQL注入 | 是 | T-T-DS01-001 |
-->

---

## 5. NIST CSF 映射

### 5.1 功能域映射

| 功能 | 类别 | 相关控制 | 符合 | 部分 | 不符合 |
|------|------|---------|------|------|--------|
| **识别 (ID)** | 资产管理 | {ID_AM_CONTROLS} | {ID_AM_PASS} | {ID_AM_PARTIAL} | {ID_AM_FAIL} |
| | 业务环境 | {ID_BE_CONTROLS} | {ID_BE_PASS} | {ID_BE_PARTIAL} | {ID_BE_FAIL} |
| | 风险评估 | {ID_RA_CONTROLS} | {ID_RA_PASS} | {ID_RA_PARTIAL} | {ID_RA_FAIL} |
| **保护 (PR)** | 访问控制 | {PR_AC_CONTROLS} | {PR_AC_PASS} | {PR_AC_PARTIAL} | {PR_AC_FAIL} |
| | 数据安全 | {PR_DS_CONTROLS} | {PR_DS_PASS} | {PR_DS_PARTIAL} | {PR_DS_FAIL} |
| | 保护技术 | {PR_PT_CONTROLS} | {PR_PT_PASS} | {PR_PT_PARTIAL} | {PR_PT_FAIL} |
| **检测 (DE)** | 异常检测 | {DE_AE_CONTROLS} | {DE_AE_PASS} | {DE_AE_PARTIAL} | {DE_AE_FAIL} |
| | 持续监控 | {DE_CM_CONTROLS} | {DE_CM_PASS} | {DE_CM_PARTIAL} | {DE_CM_FAIL} |
| **响应 (RS)** | 响应计划 | {RS_RP_CONTROLS} | {RS_RP_PASS} | {RS_RP_PARTIAL} | {RS_RP_FAIL} |
| | 缓解措施 | {RS_MI_CONTROLS} | {RS_MI_PASS} | {RS_MI_PARTIAL} | {RS_MI_FAIL} |
| **恢复 (RC)** | 恢复计划 | {RC_RP_CONTROLS} | {RC_RP_PASS} | {RC_RP_PARTIAL} | {RC_RP_FAIL} |

### 5.2 控制措施映射

| NIST 控制 | 控制描述 | 相关缓解措施 | 状态 |
|-----------|---------|-------------|------|
{NIST_CONTROLS_TABLE}
<!--
格式:
| PR.AC-1 | 身份管理 | M-001, M-003 | ✅ |
| PR.DS-1 | 静态数据保护 | M-006 | ⚠️ |
| PR.DS-2 | 传输数据保护 | M-007, M-017 | ✅ |
-->

---

## 6. 差距分析

### 6.1 未覆盖的控制

| 框架 | 控制 | 描述 | 风险影响 | 建议优先级 |
|------|------|------|---------|-----------|
{UNCOVERED_CONTROLS_TABLE}
<!--
格式:
| OWASP | A09 | 安全日志和监控 | High | P1 |
| NIST | DE.CM-1 | 网络监控 | Medium | P2 |
-->

### 6.2 部分实现的控制

| 框架 | 控制 | 当前状态 | 差距描述 | 建议措施 |
|------|------|---------|---------|---------|
{PARTIAL_CONTROLS_TABLE}
<!--
格式:
| OWASP | A01 | 基础RBAC实现 | 缺少细粒度权限控制 | M-016 |
| NIST | PR.AC-4 | 会话管理 | 缺少会话超时 | M-003 |
-->

### 6.3 建议改进

#### 短期改进 (P0-P1)

{SHORT_TERM_IMPROVEMENTS}
<!--
格式:
1. **增强访问控制** (A01)
   - 实现细粒度RBAC
   - 参考措施: M-016

2. **加强日志监控** (A09)
   - 实现安全事件日志
   - 参考措施: M-005, M-008
-->

#### 长期改进 (P2-P3)

{LONG_TERM_IMPROVEMENTS}

---

## 7. 威胁-合规映射矩阵

### 7.1 完整映射表

| 威胁ID | 风险名称 | CWE | OWASP | NIST | ISO |
|--------|---------|-----|-------|------|-----|
{THREAT_COMPLIANCE_MATRIX}
<!--
格式:
| T-S-P01-001 | JWT伪造 | CWE-347 | A07 | PR.AC-1 | A.9.4.2 |
| T-T-DS01-001 | SQL注入 | CWE-89 | A03 | PR.DS-5 | A.14.2.5 |
-->

### 7.2 热力图

```
{COMPLIANCE_HEATMAP}
```
<!--
示例:
              OWASP  CWE   NIST  ISO
威胁数量      ████   ███   ██    ██
Critical      ██     ██    █     █
High          ███    ██    ██    ██
-->

---

## 8. 合规行动计划

### 8.1 按优先级排序

| 优先级 | 合规差距 | 相关威胁 | 建议措施 | 预期影响 |
|--------|---------|---------|---------|---------|
{COMPLIANCE_ACTION_PLAN}

### 8.2 合规路线图

```
{COMPLIANCE_ROADMAP}
```
<!--
示例:
阶段 1 (P0): OWASP A03, A07 → 基础安全加固
    ↓
阶段 2 (P1): OWASP A01, A02 → 访问控制和加密
    ↓
阶段 3 (P2): OWASP A09, NIST DE → 监控和检测
    ↓
阶段 4 (P3): ISO 27001 → 管理体系完善
-->

---

## 附录

### 附录 A: 框架版本说明

| 框架 | 版本 | 发布日期 | 参考链接 |
|------|------|---------|---------|
| OWASP Top 10 | 2021 | 2021-09 | https://owasp.org/Top10/ |
| OWASP LLM Top 10 | 2023.1 | 2023-08 | https://owasp.org/www-project-top-10-for-large-language-model-applications/ |
| CWE Top 25 | 2023 | 2023-06 | https://cwe.mitre.org/top25/ |
| NIST CSF | 2.0 | 2024-02 | https://www.nist.gov/cyberframework |
| ISO 27001 | 2022 | 2022-10 | https://www.iso.org/isoiec-27001-information-security.html |

### 附录 B: 术语表

| 术语 | 定义 |
|------|------|
| 符合 | 完全满足控制要求 |
| 部分符合 | 部分满足控制要求，存在差距 |
| 不符合 | 未实现或未满足控制要求 |
| 不适用 | 控制不适用于当前项目范围 |

---

**报告结束**
