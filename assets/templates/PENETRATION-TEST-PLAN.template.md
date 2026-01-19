# 渗透测试计划: {PROJECT_NAME}

> **文档版本**: {REPORT_VERSION}
> **创建日期**: {ASSESSMENT_DATETIME}
> **分类**: 机密 - 安全测试
> **授权范围**: 仅限授权测试环境
> **有效期**: {VALIDITY_PERIOD}

---

## 1. 测试概述

### 1.1 测试目标

| 漏洞编号 | 名称 | CVSS | STRIDE | ATT&CK | 目标组件 | 优先级 |
|----------|------|------|--------|--------|----------|--------|
{TEST_TARGETS_TABLE}
<!--
格式:
| V-001 | JWT弱密钥 | 8.8 | S | T1078 | packages/cli/src/auth/ | P0 |
| V-002 | SQL注入 | 9.8 | T | T1190 | packages/core/src/db/ | P0 |
| V-003 | 权限绕过 | 7.5 | E | T1548 | packages/cli/src/authz/ | P1 |
-->

### 1.2 测试范围

| 范围 | 包含 | 排除 |
|------|------|------|
| 应用层 | {APP_SCOPE_INCLUDE} | {APP_SCOPE_EXCLUDE} |
| 网络层 | {NET_SCOPE_INCLUDE} | {NET_SCOPE_EXCLUDE} |
| 数据层 | {DATA_SCOPE_INCLUDE} | {DATA_SCOPE_EXCLUDE} |

### 1.3 授权声明

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AUTHORIZATION STATEMENT                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  本渗透测试计划仅授权在以下范围内执行:                                        │
│                                                                              │
│  - 测试环境: {AUTHORIZED_ENVIRONMENT}                                        │
│  - 测试时间: {AUTHORIZED_TIMEFRAME}                                          │
│  - 授权人员: {AUTHORIZED_PERSONNEL}                                          │
│                                                                              │
│  禁止事项:                                                                   │
│  - ❌ 在生产环境执行任何测试                                                 │
│  - ❌ 对非授权目标进行测试                                                   │
│  - ❌ 执行可能导致服务中断的测试                                             │
│  - ❌ 未经许可泄露测试结果                                                   │
│                                                                              │
│  授权签署: ________________________  日期: _______________                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. 技术架构分析

### 2.1 系统架构图

```
{SYSTEM_ARCHITECTURE_ASCII}
```
<!--
示例:
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Target System Architecture                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                              Internet                                         │
│                                 │                                            │
│                    [WAF] ◄──────┤                                            │
│                                 │                                            │
│  ═══════════════════════════════╪════════════════════════════════════════   │
│                                 │    DMZ                                     │
│  ═══════════════════════════════╪════════════════════════════════════════   │
│                                 │                                            │
│            ┌────────────────────┼────────────────────┐                      │
│            │                    │                    │                      │
│            ▼                    ▼                    ▼                      │
│       ┌─────────┐         ┌─────────┐         ┌─────────┐                  │
│       │ Web UI  │◄───────►│  API    │◄───────►│ Worker  │                  │
│       │ :443    │         │ :8080   │         │ :3000   │                  │
│       │ [V-003] │         │[V-001,2]│         │ [V-004] │                  │
│       └─────────┘         └────┬────┘         └─────────┘                  │
│                                │                                            │
│  ═══════════════════════════════╪════════════════════════════════════════   │
│                                 │    Internal                               │
│  ═══════════════════════════════╪════════════════════════════════════════   │
│                                 │                                            │
│            ┌────────────────────┼────────────────────┐                      │
│            ▼                    ▼                    ▼                      │
│       ┌─────────┐         ┌─────────┐         ┌─────────┐                  │
│       │ Redis   │         │PostgreSQL│         │ S3/Minio│                  │
│       │ :6379   │         │ :5432   │         │ :9000   │                  │
│       │ [V-005] │         │[V-002,6]│         │ [V-007] │                  │
│       └─────────┘         └─────────┘         └─────────┘                  │
│                                                                              │
│  [V-XXX] = 漏洞编号                                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
-->

### 2.2 攻击路径可视化

```
{ATTACK_PATHS_VISUALIZATION}
```
<!--
示例:
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Planned Attack Paths                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Path 1: Authentication Bypass                                               │
│  ════════════════════════════                                                │
│                                                                              │
│  [Attacker] ───► [Login API] ───► [JWT Analysis] ───► [Key Crack] ───►      │
│                                                                              │
│              ───► [Token Forge] ───► [Admin Access] ───► [Data Exfil]       │
│                                                                              │
│  Path 2: SQL Injection                                                       │
│  ═══════════════════════                                                     │
│                                                                              │
│  [Attacker] ───► [Search API] ───► [SQL Inject] ───► [DB Dump] ───►         │
│                                                                              │
│              ───► [Credential Harvest] ───► [Lateral Movement]               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
-->

---

## 3. 渗透测试用例

{PENETRATION_TEST_CASES_SECTION}

<!--
=============================================================================
渗透测试用例模板 (每个漏洞一个完整章节)
=============================================================================

### 3.X V-{XXX}: {VULNERABILITY_NAME}

#### 3.X.1 漏洞技术分析

**基本信息**:

| 属性 | 值 |
|------|-----|
| 漏洞编号 | V-{XXX} |
| 关联威胁 | T-{STRIDE}-{ELEMENT}-{SEQ} |
| CVSS评分 | {CVSS_SCORE} |
| 严重程度 | {SEVERITY} |
| 影响组件 | {AFFECTED_COMPONENT} |
| ATT&CK ID | {ATTACK_TECHNIQUE_ID} |
| ATT&CK Tactic | {ATTACK_TACTIC} |

**源代码关键位置**:

| 文件 | 行号 | 功能 | 安全风险 |
|------|------|------|---------|
| `{FILE_1}` | L{START}-L{END} | {FUNCTION_1} | {RISK_1} |
| `{FILE_2}` | L{START}-L{END} | {FUNCTION_2} | {RISK_2} |

**问题代码**:

```{CODE_LANGUAGE}
// {FILE_PATH}:L{LINE_NUMBER}
{VULNERABLE_CODE}
```

#### 3.X.2 攻击向量分析

**向量 A: {VECTOR_A_NAME}**

| 属性 | 值 |
|------|-----|
| 攻击复杂度 | {COMPLEXITY} |
| 所需权限 | {PRIVILEGES} |
| 用户交互 | {USER_INTERACTION} |
| 成功率估计 | {SUCCESS_RATE}% |

**攻击步骤**:

1. {ATTACK_STEP_1}
2. {ATTACK_STEP_2}
3. {ATTACK_STEP_3}

**向量 B: {VECTOR_B_NAME}**

[同上格式...]

#### 3.X.3 渗透测试用例

##### TC-{XXX}-001: {TEST_CASE_NAME}

**目标**: {TEST_OBJECTIVE}

**前置条件**:

- [ ] {PRECONDITION_1}
- [ ] {PRECONDITION_2}
- [ ] {PRECONDITION_3}

**测试步骤**:

```{SCRIPT_LANGUAGE}
# 步骤 1: {STEP_1_DESC}
{STEP_1_CODE}

# 步骤 2: {STEP_2_DESC}
{STEP_2_CODE}

# 步骤 3: {STEP_3_DESC}
{STEP_3_CODE}
```

**测试 Payload**:

```
Payload 1 - {PAYLOAD_1_DESC}:
{PAYLOAD_1}

Payload 2 - {PAYLOAD_2_DESC}:
{PAYLOAD_2}

Payload 3 - {PAYLOAD_3_DESC}:
{PAYLOAD_3}
```

**预期结果**: {EXPECTED_RESULT}

**实际结果**: `[待填写]`

**判定标准**:

- ✅ PASS: {PASS_CRITERIA}
- ❌ FAIL: {FAIL_CRITERIA}

**截图/证据**: `[待填写]`

---

##### TC-{XXX}-002: {TEST_CASE_NAME_2}

[同上格式...]

---

#### 3.X.4 测试矩阵

| 测试用例 | 攻击向量 | 优先级 | 风险等级 | 状态 |
|----------|----------|--------|---------|------|
| TC-{XXX}-001 | {VECTOR_A} | P0 | Critical | ⬜ 待测试 |
| TC-{XXX}-002 | {VECTOR_B} | P1 | High | ⬜ 待测试 |

---

-->

---

## 4. 测试环境准备

### 4.1 隔离测试环境

```yaml
# docker-compose.test.yml
version: '3.8'
services:
{DOCKER_COMPOSE_CONFIG}
```
<!--
示例:
  target-app:
    image: ${PROJECT_IMAGE}:${TEST_VERSION}
    ports:
      - "8080:8080"
    environment:
      - NODE_ENV=test
      - DB_HOST=postgres
      - REDIS_HOST=redis
    depends_on:
      - postgres
      - redis
    networks:
      - pentest-network

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=testdb
      - POSTGRES_USER=testuser
      - POSTGRES_PASSWORD=testpass
    volumes:
      - ./init-test-db.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - pentest-network

  redis:
    image: redis:7
    networks:
      - pentest-network

networks:
  pentest-network:
    driver: bridge
-->

### 4.2 测试数据准备

```sql
-- init-test-db.sql
{TEST_DATA_SQL}
```
<!--
示例:
-- 创建测试用户
INSERT INTO users (id, username, email, password_hash, role) VALUES
(1, 'test_user', 'test@example.com', '$2a$10$...', 'user'),
(2, 'test_admin', 'admin@example.com', '$2a$10$...', 'admin');

-- 创建测试数据
INSERT INTO sensitive_data (id, user_id, content) VALUES
(1, 1, 'Test sensitive data 1'),
(2, 1, 'Test sensitive data 2');

-- 创建测试API密钥
INSERT INTO api_keys (id, user_id, key_hash, scope) VALUES
(1, 1, '$2a$10$...', 'read'),
(2, 2, '$2a$10$...', 'admin');
-->

### 4.3 监控配置

```yaml
# prometheus.yml
{MONITORING_CONFIG}
```
<!--
示例:
global:
  scrape_interval: 5s

scrape_configs:
  - job_name: 'pentest-target'
    static_configs:
      - targets: ['target-app:8080']
    metrics_path: /metrics

  - job_name: 'pentest-traffic'
    static_configs:
      - targets: ['traffic-monitor:9090']
-->

### 4.4 测试工具配置

| 工具 | 配置文件 | 用途 |
|------|---------|------|
{TOOLS_CONFIG_TABLE}
<!--
格式:
| Burp Suite | burp-project.json | Web应用测试 |
| sqlmap | sqlmap.conf | SQL注入自动化 |
| jwt-tool | jwt-config.json | JWT测试 |
-->

---

## 5. 风险评估与缓解

### 5.1 测试风险矩阵

| 风险类型 | 描述 | 可能性 | 影响 | 缓解措施 |
|----------|------|--------|------|---------|
| 服务中断 | 测试导致目标服务崩溃 | 中 | 高 | 使用隔离环境，监控服务状态 |
| 数据损坏 | SQL注入测试损坏测试数据 | 中 | 中 | 使用数据快照，测试前备份 |
| 信息泄露 | 测试工件包含敏感信息 | 低 | 高 | 测试后清理，加密存储 |
| 范围超出 | 意外测试非授权目标 | 低 | 高 | 严格限定目标IP/域名 |
{ADDITIONAL_RISKS}

### 5.2 测试终止条件

| 条件 | 触发情况 | 处理方式 |
|------|---------|---------|
| 🔴 立即终止 | 检测到生产环境影响 | 停止所有测试，通知团队 |
| 🔴 立即终止 | 发现超出授权范围的访问 | 停止测试，记录并报告 |
| 🟠 暂停评估 | 服务响应异常 | 暂停测试，检查环境状态 |
| 🟠 暂停评估 | 发现高危漏洞 | 暂停扩展测试，优先记录POC |
| 🟡 继续监控 | 测试时间超过预期 | 评估进度，调整计划 |

### 5.3 发现报告流程

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Discovery Reporting Flow                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────┐     ┌───────────┐     ┌───────────┐     ┌───────────┐       │
│  │ 发现漏洞  │────►│ 停止测试  │────►│ 记录复现  │────►│ 评估CVSS  │       │
│  └───────────┘     └───────────┘     │   步骤    │     └─────┬─────┘       │
│                                       └───────────┘           │              │
│                                                               ▼              │
│                    ┌───────────────────────────────────────────────┐        │
│                    │              风险评级判断                      │        │
│                    └───────────────────────────────────────────────┘        │
│                           │                    │                             │
│              ┌────────────┘                    └────────────┐               │
│              ▼                                              ▼               │
│  ┌───────────────────────┐                  ┌───────────────────────┐      │
│  │ Critical/High         │                  │ Medium/Low            │      │
│  │ 48小时内报告          │                  │ 测试完成后汇总报告    │      │
│  └───────────┬───────────┘                  └───────────┬───────────┘      │
│              │                                          │                   │
│              ▼                                          ▼                   │
│  ┌───────────────────────┐                  ┌───────────────────────┐      │
│  │ 准备POC               │                  │ 记录到测试报告        │      │
│  │ 通知安全团队          │                  │ 继续其他测试          │      │
│  └───────────────────────┘                  └───────────────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. 执行计划

### 6.1 测试阶段

| 阶段 | 内容 | 预计时间 | 依赖 |
|------|------|---------|------|
| 准备 | 环境搭建，工具配置 | {PREP_TIME} | 无 |
| 侦察 | 信息收集，攻击面分析 | {RECON_TIME} | 准备完成 |
| 测试 | 执行测试用例 | {TEST_TIME} | 侦察完成 |
| 验证 | POC验证，复现 | {VERIFY_TIME} | 测试完成 |
| 报告 | 整理报告，建议 | {REPORT_TIME} | 验证完成 |

### 6.2 测试用例执行顺序

| 顺序 | 漏洞编号 | 测试用例 | 优先级 | 预计时间 |
|------|---------|---------|--------|---------|
{TEST_EXECUTION_ORDER}
<!--
格式:
| 1 | V-001 | TC-001-001, TC-001-002 | P0 | 2h |
| 2 | V-002 | TC-002-001 | P0 | 1.5h |
| 3 | V-003 | TC-003-001, TC-003-002, TC-003-003 | P1 | 3h |
-->

### 6.3 资源需求

| 资源 | 需求 | 说明 |
|------|------|------|
| 测试人员 | {PERSONNEL_COUNT} | {PERSONNEL_SKILLS} |
| 测试环境 | {ENV_SPECS} | {ENV_NOTES} |
| 工具许可 | {TOOL_LICENSES} | {LICENSE_NOTES} |

---

## 附录

### 附录 A: CVSS 评分详情

| 漏洞编号 | CVSS向量 | 评分 |
|----------|---------|------|
{CVSS_DETAILS_TABLE}
<!--
格式:
| V-001 | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.8 |
| V-002 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
-->

### 附录 B: 相关 CVE/CWE

| 漏洞编号 | CWE | 相关CVE | 参考 |
|----------|-----|---------|------|
{CVE_CWE_TABLE}
<!--
格式:
| V-001 | CWE-347 | CVE-2023-XXXXX | https://... |
| V-002 | CWE-89 | CVE-2022-XXXXX | https://... |
-->

### 附录 C: 测试检查清单

```
[ ] 测试环境已隔离
[ ] 测试数据已准备
[ ] 监控已配置
[ ] 工具已配置
[ ] 授权已确认
[ ] 备份已创建
[ ] 终止条件已理解
[ ] 报告流程已理解
```

### 附录 D: 联系方式

| 角色 | 姓名 | 联系方式 | 备注 |
|------|------|---------|------|
| 测试负责人 | {TEST_LEAD} | {TEST_LEAD_CONTACT} | |
| 安全团队 | {SECURITY_TEAM} | {SECURITY_CONTACT} | 紧急情况 |
| 开发团队 | {DEV_TEAM} | {DEV_CONTACT} | 技术问题 |
| 运维团队 | {OPS_TEAM} | {OPS_CONTACT} | 环境问题 |

### 附录 E: MITRE ATT&CK 技术映射

#### E.1 STRIDE → ATT&CK 映射参考

| STRIDE | ATT&CK Tactic | 常见 Techniques | 描述 |
|--------|--------------|-----------------|------|
| **S**poofing | Initial Access | T1078 (Valid Accounts) | 使用有效凭证获取访问 |
| | Initial Access | T1566 (Phishing) | 通过钓鱼获取凭证 |
| | Credential Access | T1110 (Brute Force) | 暴力破解认证 |
| | Credential Access | T1539 (Steal Web Session Cookie) | 窃取会话凭证 |
| **T**ampering | Impact | T1485 (Data Destruction) | 破坏数据完整性 |
| | Impact | T1565 (Data Manipulation) | 篡改数据 |
| | Initial Access | T1190 (Exploit Public-Facing App) | 利用应用漏洞 |
| | Persistence | T1505 (Server Software Component) | 植入后门 |
| **R**epudiation | Defense Evasion | T1070 (Indicator Removal) | 清除日志痕迹 |
| | Defense Evasion | T1036 (Masquerading) | 伪装活动 |
| | Defense Evasion | T1562 (Impair Defenses) | 禁用审计功能 |
| **I**nfo Disclosure | Collection | T1005 (Data from Local System) | 本地数据收集 |
| | Collection | T1039 (Data from Network Shared Drive) | 网络数据收集 |
| | Exfiltration | T1048 (Exfiltration Over Alternative Protocol) | 数据外泄 |
| | Discovery | T1083 (File and Directory Discovery) | 敏感文件发现 |
| **D**enial of Service | Impact | T1499 (Endpoint DoS) | 端点拒绝服务 |
| | Impact | T1498 (Network DoS) | 网络拒绝服务 |
| | Impact | T1489 (Service Stop) | 服务停止 |
| **E**levation | Privilege Escalation | T1068 (Exploitation for Privilege Escalation) | 漏洞提权 |
| | Privilege Escalation | T1548 (Abuse Elevation Control Mechanism) | 滥用提权机制 |
| | Privilege Escalation | T1134 (Access Token Manipulation) | 令牌操作 |

#### E.2 本项目 ATT&CK 技术清单

| 漏洞编号 | ATT&CK ID | 技术名称 | Tactic | 检测方法 |
|----------|-----------|---------|--------|---------|
{ATTACK_TECHNIQUES_TABLE}
<!--
格式:
| V-001 | T1078.001 | Valid Accounts: Default Accounts | Initial Access | 监控默认凭证使用 |
| V-002 | T1190 | Exploit Public-Facing Application | Initial Access | WAF日志分析 |
| V-003 | T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC | Privilege Escalation | 进程监控 |
-->

#### E.3 ATT&CK 攻击链分析

```
{ATTACK_CHAIN_DIAGRAM}
```
<!--
示例:
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ATT&CK Attack Chain Analysis                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  攻击链 1: 凭证窃取 → 权限提升 → 数据外泄                                    │
│  ════════════════════════════════════════════                                │
│                                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Initial  │    │Credential│    │Privilege │    │Exfiltrat │              │
│  │ Access   │───►│ Access   │───►│Escalation│───►│   ion    │              │
│  │ T1078    │    │ T1539    │    │ T1548    │    │ T1048    │              │
│  │ V-001    │    │ V-004    │    │ V-003    │    │ V-007    │              │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘              │
│                                                                              │
│  攻击链 2: 应用漏洞 → 代码执行 → 持久化                                      │
│  ═════════════════════════════════════════                                   │
│                                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                               │
│  │ Initial  │    │Execution │    │Persistence│                              │
│  │ Access   │───►│          │───►│           │                              │
│  │ T1190    │    │ T1059    │    │ T1505     │                              │
│  │ V-002    │    │ V-005    │    │ V-006     │                              │
│  └──────────┘    └──────────┘    └──────────┘                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
-->

#### E.4 ATT&CK 检测与响应建议

| ATT&CK ID | 检测数据源 | 检测规则示例 | 响应措施 |
|-----------|-----------|-------------|---------|
{ATTACK_DETECTION_TABLE}
<!--
格式:
| T1078 | 认证日志 | 异常登录地点/时间 | 强制MFA，账户锁定 |
| T1190 | WAF日志 | SQL注入/XSS模式 | 阻断请求，安全告警 |
| T1548 | 进程监控 | 权限提升尝试 | 终止进程，安全审计 |
-->

---

**文档结束**

---

> **安全声明**: 本渗透测试计划包含敏感安全信息，包括攻击方法和POC代码。
> 请严格限制访问范围，仅供授权安全测试人员使用。
> 所有测试活动必须在授权范围内进行。
> 未经授权禁止传播或用于非法目的。
