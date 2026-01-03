<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

# 数据流图报告: {PROJECT_NAME}

> **评估时间**: {ASSESSMENT_DATETIME}
> **分析师**: Claude (Deep Risk Analysis)
> **框架版本**: STRIDE-TM v1.0.2
> **报告版本**: {REPORT_VERSION}

---

## 1. DFD 概览

### 1.1 Level 0 上下文图

```
{LEVEL0_CONTEXT_DIAGRAM}
```
<!--
示例:
                              ┌─────────────────────────────┐
                              │                             │
         ┌─────────────┐      │     ┌───────────────┐      │      ┌─────────────┐
         │             │      │     │               │      │      │             │
         │    User     │◄────►│     │   {SYSTEM}    │◄────►│      │  External   │
         │  (Browser)  │      │     │               │      │      │   Service   │
         │             │      │     └───────────────┘      │      │             │
         └─────────────┘      │                             │      └─────────────┘
                              │      Trust Boundary         │
                              └─────────────────────────────┘
-->

### 1.2 Level 1 系统图

```
{LEVEL1_SYSTEM_DIAGRAM}
```
<!--
示例:
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Level 1: System Data Flow                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│    ┌─────────┐                                                                  │
│    │  EI01   │                                                                  │
│    │  User   │                                                                  │
│    └────┬────┘                                                                  │
│         │ DF01: HTTP Request (credentials)                                      │
│         ▼                                                                        │
│   ══════════════════════════════════ TB01: Network Boundary ════════════════    │
│         │                                                                        │
│         ▼                                                                        │
│    ┌─────────┐       DF02: Auth Request       ┌─────────┐                       │
│    │   P01   │──────────────────────────────►│   P02   │                       │
│    │ Web App │                                │Auth Svc │                       │
│    └────┬────┘                                └────┬────┘                       │
│         │                                          │                             │
│         │ DF03: Data Request                       │ DF04: Token Verify          │
│         ▼                                          ▼                             │
│    ┌─────────┐       DF05: Query              ┌─────────┐                       │
│    │   P03   │──────────────────────────────►│  DS01   │                       │
│    │ API Svc │◄──────────────────────────────│Database │                       │
│    └─────────┘       DF06: Results            └─────────┘                       │
│                                                                                  │
│   ══════════════════════════════════ TB02: Process Boundary ════════════════    │
│                                                                                  │
│    ┌─────────┐                                                                  │
│    │  EI02   │                                                                  │
│    │External │◄─── DF07: Webhook ────────────────────────────────────────────   │
│    │  API    │                                                                  │
│    └─────────┘                                                                  │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
-->

### 1.3 DFD 统计

| 元素类型 | 数量 | 威胁关联数 |
|---------|------|-----------|
| 进程 (Process) | {PROCESS_COUNT} | {PROCESS_THREATS} |
| 数据存储 (Data Store) | {DS_COUNT} | {DS_THREATS} |
| 数据流 (Data Flow) | {DF_COUNT} | {DF_THREATS} |
| 外部实体 (External Entity) | {EI_COUNT} | N/A |
| 信任边界 (Trust Boundary) | {TB_COUNT} | N/A |
| **总计** | **{TOTAL_ELEMENTS}** | **{TOTAL_THREATS}** |

---

## 2. DFD 元素清单

### 2.1 进程 (Processes)

| ID | 名称 | 描述 | 技术 | 认证 | 授权 | 威胁数 |
|----|------|------|------|------|------|--------|
{PROCESSES_TABLE}
<!--
格式:
| P01 | Web Application | 前端Web应用 | React/Next.js | Session | RBAC | 5 |
| P02 | Authentication Service | 认证服务 | Node.js/Express | N/A | N/A | 8 |
| P03 | API Service | 后端API服务 | Node.js/Express | JWT | RBAC | 12 |
-->

#### 进程详情

{PROCESS_DETAILS_SECTION}
<!--
格式:
##### P01: Web Application

**描述**: {DESCRIPTION}

**技术栈**: {TECH_STACK}

**安全属性**:
| 属性 | 值 |
|------|-----|
| Code Type | Web |
| Running As | User |
| Isolation Level | AppContainer |
| Implements Authentication | Yes |
| Implements Authorization | Yes |
| Input Sanitization | Yes |
| Output Encoding | Yes |

**威胁关联**: T-S-P01-001, T-T-P01-001, ...
-->

### 2.2 数据存储 (Data Stores)

| ID | 名称 | 类型 | 描述 | 敏感数据 | 加密 | 威胁数 |
|----|------|------|------|---------|------|--------|
{DATA_STORES_TABLE}
<!--
格式:
| DS01 | PostgreSQL | RDBMS | 主数据库 | PII, 凭证 | 静态加密 | 6 |
| DS02 | Redis | Cache | 会话缓存 | Session | 无 | 3 |
| DS03 | S3 Bucket | Object Store | 文件存储 | 文档 | 服务端加密 | 2 |
-->

#### 数据存储详情

{DATA_STORE_DETAILS_SECTION}
<!--
格式:
##### DS01: PostgreSQL Database

**描述**: {DESCRIPTION}

**技术**: PostgreSQL {VERSION}

**安全属性**:
| 属性 | 值 |
|------|-----|
| Stores Credentials | Yes |
| Stores Logs | No |
| Encrypted | Yes (AES-256) |
| Signed | N/A |
| Backup Enabled | Yes |

**敏感数据分类**:
- PII: 用户姓名、邮箱、电话
- 凭证: 密码哈希、API密钥
- 业务数据: 订单、交易记录

**威胁关联**: T-T-DS01-001, T-I-DS01-001, ...
-->

### 2.3 数据流 (Data Flows)

| ID | 名称 | 源 | 目标 | 协议 | 加密 | 认证 | 威胁数 |
|----|------|-----|------|------|------|------|--------|
{DATA_FLOWS_TABLE}
<!--
格式:
| DF01 | User Request | EI01 | P01 | HTTPS | TLS 1.3 | Session | 3 |
| DF02 | Auth Request | P01 | P02 | gRPC | mTLS | Internal | 2 |
| DF03 | DB Query | P03 | DS01 | TCP | 无 | Password | 4 |
-->

#### 数据流详情

{DATA_FLOW_DETAILS_SECTION}
<!--
格式:
##### DF01: User HTTP Request

**描述**: 用户浏览器到Web应用的HTTP请求

**路径**: EI01 (User) → P01 (Web App)

**安全属性**:
| 属性 | 值 |
|------|-----|
| Protocol | HTTPS |
| Encrypted | Yes (TLS 1.3) |
| Authenticated | Yes (Session/JWT) |
| Data Classification | User Input |

**传输数据**:
- 用户凭证 (登录时)
- 用户输入
- 文件上传

**威胁关联**: T-T-DF01-001, T-I-DF01-001, ...
-->

### 2.4 外部实体 (External Entities)

| ID | 名称 | 类型 | 描述 | 信任级别 |
|----|------|------|------|---------|
{EXTERNAL_ENTITIES_TABLE}
<!--
格式:
| EI01 | User | Human | 系统用户（浏览器） | Untrusted |
| EI02 | Admin | Human | 管理员用户 | Partially Trusted |
| EI03 | External API | System | 第三方API服务 | Partially Trusted |
| EI04 | Webhook Sender | System | Webhook调用方 | Untrusted |
-->

---

## 3. 信任边界

### 3.1 边界定义

| ID | 名称 | 类型 | 描述 |
|----|------|------|------|
{TRUST_BOUNDARIES_TABLE}
<!--
格式:
| TB01 | Internet-DMZ | Network | 互联网到DMZ区域 |
| TB02 | DMZ-Internal | Network | DMZ到内部网络 |
| TB03 | Application-Database | Process | 应用层到数据层 |
| TB04 | User-Admin | User | 普通用户到管理员 |
-->

#### 边界详情

{TRUST_BOUNDARY_DETAILS_SECTION}
<!--
格式:
##### TB01: Internet-DMZ Boundary

**类型**: Network

**描述**: 公网到内部DMZ区域的网络边界

**内部元素**:
- P01: Web Application
- P02: API Gateway

**穿越数据流**:
| 数据流 | 方向 | 安全控制 |
|--------|------|---------|
| DF01 | Inbound | TLS, WAF, Rate Limit |
| DF10 | Outbound | TLS |

**安全控制**:
- [ ] 防火墙
- [ ] WAF
- [ ] DDoS 防护
- [ ] TLS 终止
-->

### 3.2 边界穿越分析

| 数据流 | 穿越边界 | 方向 | 数据分类 | 安全控制 | 风险等级 |
|--------|---------|------|---------|---------|---------|
{BOUNDARY_CROSSING_TABLE}
<!--
格式:
| DF01 | TB01 | Inbound | User Input | TLS, Validation | Medium |
| DF02 | TB02 | Internal | Auth Token | mTLS | Low |
| DF03 | TB03 | Internal | SQL Query | None | High |
-->

### 3.3 关键接口

| 接口 | 类型 | 边界 | 安全机制 | 风险等级 |
|------|------|------|---------|---------|
{CRITICAL_INTERFACES_TABLE}
<!--
格式:
| API Gateway | HTTP | TB01 | JWT, Rate Limit | High |
| Database Connection | TCP | TB03 | Password Auth | Critical |
| Cache Connection | TCP | TB02 | None | High |
-->

---

## 4. 敏感数据流

### 4.1 PII 数据流

```
{PII_DATA_FLOW_DIAGRAM}
```
<!--
示例:
PII Data Flow Path:

    EI01 (User Input)
         │
         │ DF01: name, email, phone
         ▼
    P01 (Web App) ─────► P02 (API) ─────► DS01 (Database)
                                               │
                                               │ stored: hashed
                                               ▼
                                         [Encrypted at Rest]
-->

**PII 数据类型**:
| 数据类型 | 来源 | 处理位置 | 存储位置 | 加密状态 |
|---------|------|---------|---------|---------|
{PII_DATA_TABLE}

### 4.2 凭证数据流

```
{CREDENTIAL_DATA_FLOW_DIAGRAM}
```

**凭证类型**:
| 凭证类型 | 来源 | 传输加密 | 存储加密 | 访问控制 |
|---------|------|---------|---------|---------|
{CREDENTIAL_DATA_TABLE}

### 4.3 其他敏感数据

| 数据类型 | 敏感级别 | 数据流路径 | 保护措施 |
|---------|---------|-----------|---------|
{OTHER_SENSITIVE_DATA_TABLE}

---

## 5. 安全发现汇总 (Phase 2-3)

### 5.1 发现统计

| 严重程度 | Phase 2 | Phase 3 | 总计 |
|---------|---------|---------|------|
| Critical | {P2_CRITICAL} | {P3_CRITICAL} | {TOTAL_CRITICAL} |
| High | {P2_HIGH} | {P3_HIGH} | {TOTAL_HIGH} |
| Medium | {P2_MEDIUM} | {P3_MEDIUM} | {TOTAL_MEDIUM} |
| Low | {P2_LOW} | {P3_LOW} | {TOTAL_LOW} |

### 5.2 发现清单

| 发现ID | 阶段 | 类型 | 标题 | 位置 | 严重程度 |
|--------|------|------|------|------|---------|
{P2_P3_FINDINGS_TABLE}

### 5.3 阶段反思

**Phase 2 关键发现**:
{P2_KEY_FINDINGS}

**Phase 3 关键发现**:
{P3_KEY_FINDINGS}

**传递给 Phase 4-5**:
{P2_P3_HANDOVER}

---

## 附录

### 附录 A: Mermaid DFD 源码

#### Level 0 Context Diagram

```mermaid
{MERMAID_LEVEL0}
```

#### Level 1 System Diagram

```mermaid
{MERMAID_LEVEL1}
```

### 附录 B: 元素属性详情

#### B.1 进程属性

{PROCESS_ATTRIBUTES_TABLE}
<!--
格式:
| ID | Code Type | Running As | Isolation | Auth | Authz | Input San. | Output Enc. |
|----|-----------|------------|-----------|------|-------|------------|-------------|
| P01 | Web | User | AppContainer | Yes | Yes | Yes | Yes |
-->

#### B.2 数据存储属性

{DATA_STORE_ATTRIBUTES_TABLE}
<!--
格式:
| ID | Stores Creds | Stores Logs | Encrypted | Signed | Backup |
|----|--------------|-------------|-----------|--------|--------|
| DS01 | Yes | No | Yes | N/A | Yes |
-->

#### B.3 数据流属性

{DATA_FLOW_ATTRIBUTES_TABLE}
<!--
格式:
| ID | Protocol | Encrypted | Authenticated | Data Classification |
|----|----------|-----------|---------------|---------------------|
| DF01 | HTTPS | Yes (TLS 1.3) | Yes | User Input |
-->

---

**报告结束**
