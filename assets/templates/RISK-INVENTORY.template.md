# 风险清单报告: {PROJECT_NAME}

> **评估时间**: {ASSESSMENT_DATETIME}
> **分析师**: Claude (STRIDE Deep Threat Modeling)
> **框架版本**: STRIDE-TM v1.0.2
> **报告版本**: {REPORT_VERSION}
> **总风险数**: {TOTAL_RISK_COUNT}

---

## 1. 风险统计摘要

### 1.1 按严重程度统计

| 严重程度 | 数量 | 百分比 | 说明 |
|---------|------|--------|------|
| 🔴 **Critical** | {CRITICAL_COUNT} | {CRITICAL_PCT}% | CVSS 9.0-10.0，需立即修复 |
| 🟠 **High** | {HIGH_COUNT} | {HIGH_PCT}% | CVSS 7.0-8.9，7天内修复 |
| 🟡 **Medium** | {MEDIUM_COUNT} | {MEDIUM_PCT}% | CVSS 4.0-6.9，30天内修复 |
| 🟢 **Low** | {LOW_COUNT} | {LOW_PCT}% | CVSS 0.1-3.9，计划中修复 |
| **总计** | **{TOTAL_COUNT}** | **100%** | |

### 1.2 按 STRIDE 类别统计

| STRIDE | 名称 | 数量 | 占比 | Critical | High | Medium | Low |
|--------|------|------|------|----------|------|--------|-----|
| **S** | Spoofing (欺骗) | {S_COUNT} | {S_PCT}% | {S_CRITICAL} | {S_HIGH} | {S_MEDIUM} | {S_LOW} |
| **T** | Tampering (篡改) | {T_COUNT} | {T_PCT}% | {T_CRITICAL} | {T_HIGH} | {T_MEDIUM} | {T_LOW} |
| **R** | Repudiation (抵赖) | {R_COUNT} | {R_PCT}% | {R_CRITICAL} | {R_HIGH} | {R_MEDIUM} | {R_LOW} |
| **I** | Info Disclosure (信息泄露) | {I_COUNT} | {I_PCT}% | {I_CRITICAL} | {I_HIGH} | {I_MEDIUM} | {I_LOW} |
| **D** | DoS (拒绝服务) | {D_COUNT} | {D_PCT}% | {D_CRITICAL} | {D_HIGH} | {D_MEDIUM} | {D_LOW} |
| **E** | EoP (权限提升) | {E_COUNT} | {E_PCT}% | {E_CRITICAL} | {E_HIGH} | {E_MEDIUM} | {E_LOW} |
| **总计** | | **{TOTAL_COUNT}** | **100%** | {TOTAL_CRITICAL} | {TOTAL_HIGH} | {TOTAL_MEDIUM} | {TOTAL_LOW} |

### 1.3 按组件分布统计

| 组件 | 元素ID | 风险数 | 最高等级 | 高风险比例 |
|------|--------|--------|---------|-----------|
{COMPONENT_DISTRIBUTION_TABLE}
<!--
格式:
| API Gateway | P01 | 12 | 🔴 Critical | 67% |
| Auth Service | P02 | 8 | 🔴 Critical | 50% |
| Database | DS01 | 6 | 🟠 High | 33% |
| Frontend | P03 | 4 | 🟡 Medium | 0% |
-->

### 1.4 按状态统计

| 状态 | 数量 | 百分比 |
|------|------|--------|
| 待修复 (Pending) | {PENDING_COUNT} | {PENDING_PCT}% |
| 进行中 (In Progress) | {INPROGRESS_COUNT} | {INPROGRESS_PCT}% |
| 已缓解 (Mitigated) | {MITIGATED_COUNT} | {MITIGATED_PCT}% |
| 已接受 (Accepted) | {ACCEPTED_COUNT} | {ACCEPTED_PCT}% |
| 误报 (False Positive) | {FP_COUNT} | {FP_PCT}% |

### 1.5 数量守恒验证 (Count Conservation)

> ⚠️ **此表用于验证威胁到风险的转换完整性**

| 检查项 | 数量 | 说明 |
|--------|------|------|
| P5 威胁总数 | {P5_THREAT_TOTAL} | 来自 P5-STRIDE-THREATS.md |
| 合并为 VR 的威胁 | {THREATS_CONSOLIDATED} | 通过 threat_refs 追溯 |
| 排除的威胁 | {THREATS_EXCLUDED} | 附有排除理由 |
| **守恒验证** | **{CONSERVATION_STATUS}** | `{THREATS_CONSOLIDATED} + {THREATS_EXCLUDED} = {P5_THREAT_TOTAL}` |

<!--
验证规则:
✅ 守恒通过: THREATS_CONSOLIDATED + THREATS_EXCLUDED = P5_THREAT_TOTAL
❌ 守恒失败: 有威胁丢失，需检查 P6 threat_disposition 表
-->

---

## 2. 风险汇总表

### 2.1 Critical 风险

| 风险ID | STRIDE | 元素 | 风险名称 | Threat Refs | CWE | CVSS | 状态 |
|--------|--------|------|---------|-------------|-----|------|------|
{CRITICAL_RISKS_TABLE}
<!--
格式示例:
| VR-001 | T,E | P13 | 代码执行风险 | T-T-P13-001, T-T-P13-002, T-E-P13-001 | CWE-94 | 10.0 | Pending |
注意: Threat Refs 列追溯到 P5 原始威胁，用于数量守恒验证
-->

### 2.2 High 风险

| 风险ID | STRIDE | 元素 | 风险名称 | Threat Refs | CWE | CVSS | 状态 |
|--------|--------|------|---------|-------------|-----|------|------|
{HIGH_RISKS_TABLE}

### 2.3 Medium 风险

| 风险ID | STRIDE | 元素 | 风险名称 | Threat Refs | CWE | CVSS | 状态 |
|--------|--------|------|---------|-------------|-----|------|------|
{MEDIUM_RISKS_TABLE}

### 2.4 Low 风险

| 风险ID | STRIDE | 元素 | 风险名称 | Threat Refs | CWE | CVSS | 状态 |
|--------|--------|------|---------|-------------|-----|------|------|
{LOW_RISKS_TABLE}

---

## 3. 风险详情

<!--
每个风险的完整详情块，按 risk-detail.schema.md 定义的格式
Critical 和 High 风险必须有完整详情
Medium 和 Low 风险可使用简化格式
-->

{RISK_DETAILS_SECTION}

<!--
=============================================================================
风险详情模板 (完整格式 - Critical/High 必需)
=============================================================================

### VR-{SEQ}: {RISK_NAME}

**基本信息**:

| 属性 | 值 |
|------|-----|
| 风险ID | VR-{SEQ} |
| **Threat Refs** | {THREAT_REFS} |
| STRIDE类型 | {STRIDE_FULL_NAME} |
| 受影响元素 | {ELEMENT_ID} - {ELEMENT_NAME} |
| 严重程度 | {SEVERITY_ICON} {SEVERITY} |
| CVSS评分 | {CVSS_SCORE} |
| CVSS向量 | `{CVSS_VECTOR}` |

<!--
THREAT_REFS 示例: T-T-P13-001, T-T-P13-002, T-E-P13-001
追溯到 P5-STRIDE-THREATS.md 中的原始威胁 ID
此字段必填，用于保证数量守恒验证
-->

**风险描述**:

{DESCRIPTION_BRIEF}

**详细说明**:

{DESCRIPTION_DETAILED}

**位置定位**:

- **组件**: {LOCATION_COMPONENT}
- **文件**: `{LOCATION_FILE}:{LOCATION_LINE_RANGE}`
- **关键代码**:

```{CODE_LANGUAGE}
{LOCATION_CODE_SNIPPET}
```

**原因分析**:

- **根本原因**: {ROOT_CAUSE}
- **贡献因素**:
  - {CONTRIBUTING_FACTOR_1}
  - {CONTRIBUTING_FACTOR_2}
- **相关CWE**: [{RELATED_CWE}]({CWE_URL}) - {CWE_NAME}
- **相关CAPEC**: [{RELATED_CAPEC}]({CAPEC_URL}) - {CAPEC_NAME}

**攻击路径**:

```
{ATTACK_PATH}
```

**前置条件**:

1. {PREREQUISITE_1}
2. {PREREQUISITE_2}
3. {PREREQUISITE_3}

**ATT&CK映射**: [{ATTCK_TECHNIQUE}]({ATTCK_URL}) - {ATTCK_NAME}

**POC验证方法**:

**类型**: {POC_TYPE} (manual/automated/command/script)

**描述**: {POC_DESCRIPTION}

```{POC_LANGUAGE}
{POC_COMMAND}
```

**可利用性**: {EXPLOITABILITY} (Very High/High/Medium/Low)

**影响评估**:

| 维度 | 影响程度 | 说明 |
|------|---------|------|
| 机密性 (C) | {IMPACT_C} | {IMPACT_C_DESC} |
| 完整性 (I) | {IMPACT_I} | {IMPACT_I_DESC} |
| 可用性 (A) | {IMPACT_A} | {IMPACT_A_DESC} |

**缓解措施**:

**优先级**: {MITIGATION_PRIORITY}

| 优先级 | 说明 |
|--------|------|
| P0 | 立即修复 - Critical 风险，可能已被利用 |
| P1 | 紧急 - High 风险，7天内修复 |
| P2 | 高优先级 - Medium 风险，30天内修复 |
| P3 | 计划中 - Low 风险，规划中修复 |

**缓解策略**:

{MITIGATION_STRATEGY}

**短期修复** (优先级: {SHORT_TERM_PRIORITY}):

{SHORT_TERM_DESCRIPTION}

```{SHORT_TERM_LANGUAGE}
{SHORT_TERM_IMPLEMENTATION}
```

**长期方案** (优先级: {LONG_TERM_PRIORITY}):

{LONG_TERM_DESCRIPTION}

```{LONG_TERM_LANGUAGE}
{LONG_TERM_IMPLEMENTATION}
```

**KB参考**: {KB_REFERENCE}

---

=============================================================================
风险详情模板 (简化格式 - Medium/Low 可选)
=============================================================================

### VR-{SEQ}: {RISK_NAME}

| 属性 | 值 |
|------|-----|
| **Threat Refs** | {THREAT_REFS} |
| STRIDE | {STRIDE_FULL_NAME} |
| 元素 | {ELEMENT_ID} - {ELEMENT_NAME} |
| 严重程度 | {SEVERITY_ICON} {SEVERITY} |
| CVSS | {CVSS_SCORE} |
| CWE | {RELATED_CWE} |
| 位置 | `{LOCATION_FILE}` |

**描述**: {DESCRIPTION_BRIEF}

**缓解**: {MITIGATION_STRATEGY}

---

-->

---

## 4. 风险趋势分析

### 4.1 风险分布热力图

```
{RISK_HEATMAP}
```
<!--
示例:
组件              S    T    R    I    D    E    总计  风险等级
───────────────────────────────────────────────────────────────
API Gateway      ██   ███  █    ██   ██   ███   12   ████████ Critical
Auth Service     ███  ██   ░    █    ░    ██     8   ██████   High
Database         ░    ███  ░    ██   █    █      6   █████    High
Frontend         █    █    ░    █    █    ░      4   ███      Medium
Worker           ░    ░    ░    █    █    ░      2   ██       Low

图例: ███ Critical  ██ High  █ Medium  ░ Low/None
-->

### 4.2 风险关联图

```
{RISK_CORRELATION_MAP}
```
<!--
示例:
T-S-P01-001 (JWT伪造) ────┬──► T-E-P01-002 (权限提升)
                         │
                         └──► T-T-DS01-001 (数据篡改)
                                    │
                                    └──► T-I-DS01-002 (数据泄露)
-->

---

## 5. 附加信息

### 5.1 CWE 分布

| CWE | 名称 | 风险数 | 严重程度 |
|-----|------|--------|---------|
{CWE_DISTRIBUTION_TABLE}

### 5.2 ATT&CK 映射汇总

| 战术 | 技术 | 风险数 | 相关威胁 |
|------|------|--------|---------|
{ATTCK_MAPPING_TABLE}

### 5.3 知识库查询记录

| 查询类型 | 参数 | 结果数 | 使用于 |
|---------|------|--------|-------|
{KB_QUERY_LOG}

---

**报告结束**

---

> **注意**: 本风险清单应与缓解措施报告 ({PROJECT_NAME}-MITIGATION-MEASURES.md)
> 和攻击路径验证报告 ({PROJECT_NAME}-ATTACK-PATH-VALIDATION.md) 结合使用。
