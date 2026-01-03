<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

# 架构分析报告: {PROJECT_NAME}

> **评估时间**: {ASSESSMENT_DATETIME}
> **分析师**: Claude (Deep Risk Analysis)
> **框架版本**: STRIDE-TM v1.0.2
> **报告版本**: {REPORT_VERSION}

---

## 1. 项目概述

### 1.1 项目类型和目的

| 属性 | 值 |
|------|-----|
| **项目名称** | {PROJECT_NAME} |
| **项目类型** | {PROJECT_TYPE} |
| **主要功能** | {PRIMARY_FUNCTION} |
| **目标用户** | {TARGET_USERS} |
| **部署模式** | {DEPLOYMENT_MODE} |

**项目描述**:

{PROJECT_DESCRIPTION}

### 1.2 技术栈摘要

| 层级 | 技术选型 | 版本 | 说明 |
|------|---------|------|------|
| **编程语言** | {LANGUAGE} | {LANG_VERSION} | {LANG_NOTES} |
| **运行时** | {RUNTIME} | {RUNTIME_VERSION} | {RUNTIME_NOTES} |
| **Web框架** | {FRAMEWORK} | {FRAMEWORK_VERSION} | {FRAMEWORK_NOTES} |
| **ORM/数据层** | {ORM} | {ORM_VERSION} | {ORM_NOTES} |
| **数据库** | {DATABASE} | {DB_VERSION} | {DB_NOTES} |
| **缓存** | {CACHE} | {CACHE_VERSION} | {CACHE_NOTES} |
| **消息队列** | {MQ} | {MQ_VERSION} | {MQ_NOTES} |
| **容器化** | {CONTAINER} | {CONTAINER_VERSION} | {CONTAINER_NOTES} |

### 1.3 代码结构概览

```
{CODEBASE_TREE}
```
<!--
示例:
project-root/
├── packages/
│   ├── cli/                 # 后端 CLI 和 API
│   │   ├── src/
│   │   │   ├── controllers/ # API 控制器
│   │   │   ├── services/    # 业务逻辑
│   │   │   ├── auth/        # 认证模块 ★
│   │   │   └── security/    # 安全相关 ★
│   │   └── config/          # 配置
│   ├── core/                # 核心引擎
│   ├── editor-ui/           # 前端 Vue 应用
│   └── workflow/            # 工作流定义
├── docker/                  # Docker 配置
└── scripts/                 # 构建脚本

★ = 安全相关模块
-->

**代码统计**:

| 指标 | 数值 |
|------|------|
| 总文件数 | {TOTAL_FILES} |
| 代码行数 | {TOTAL_LOC} |
| 主要模块数 | {MODULE_COUNT} |
| 安全相关模块 | {SECURITY_MODULES} |

---

## 2. 组件拓扑

### 2.1 高层架构图

```
{HIGH_LEVEL_ARCHITECTURE_ASCII}
```
<!--
示例:
┌─────────────────────────────────────────────────────────────────────────────┐
│                              External Layer                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Browser   │  │  Mobile App │  │  API Client │  │  Webhook    │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
└─────────┼────────────────┼────────────────┼────────────────┼────────────────┘
          │                │                │                │
          └────────────────┴────────────────┴────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Edge Layer                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Load Balancer / CDN                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Application Layer                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Web Server │  │  API Server │  │  Worker     │  │  Scheduler  │        │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘        │
│         │                │                │                │                │
│         └────────────────┴────────────────┴────────────────┘                │
│                                   │                                          │
└───────────────────────────────────┼──────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Data Layer                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  PostgreSQL │  │    Redis    │  │  S3/Storage │  │  Secrets    │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
-->

### 2.2 模块依赖关系

```
{MODULE_DEPENDENCY_GRAPH}
```
<!--
示例:
┌─────────────────────────────────────────────────────────────────┐
│                     Module Dependencies                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  editor-ui ──────────────────────────────────┐                  │
│      │                                        │                  │
│      ▼                                        ▼                  │
│  api-types ◄─────── cli ◄─────── core ◄─────── workflow        │
│      │                │            │                             │
│      ▼                ▼            ▼                             │
│  design-system    db-models    nodes-base                        │
│                       │                                          │
│                       ▼                                          │
│                   config                                         │
│                                                                  │
│  图例: A ──► B 表示 A 依赖 B                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
-->

### 2.3 外部服务集成

| 服务类型 | 服务名称 | 集成方式 | 认证方式 | 安全注意事项 |
|---------|---------|---------|---------|-------------|
| {SVC_TYPE_1} | {SVC_NAME_1} | {INTEGRATION_1} | {AUTH_1} | {SECURITY_NOTE_1} |
| {SVC_TYPE_2} | {SVC_NAME_2} | {INTEGRATION_2} | {AUTH_2} | {SECURITY_NOTE_2} |
| {SVC_TYPE_3} | {SVC_NAME_3} | {INTEGRATION_3} | {AUTH_3} | {SECURITY_NOTE_3} |

---

## 3. 技术栈详情

### 3.1 编程语言和框架

#### 主要语言

| 语言 | 版本 | 使用范围 | 安全特性 |
|------|------|---------|---------|
| {LANG_1} | {VER_1} | {SCOPE_1} | {SECURITY_1} |
| {LANG_2} | {VER_2} | {SCOPE_2} | {SECURITY_2} |

#### 框架

| 框架 | 版本 | 用途 | 内置安全功能 |
|------|------|------|------------|
| {FW_1} | {FW_VER_1} | {FW_USE_1} | {FW_SECURITY_1} |
| {FW_2} | {FW_VER_2} | {FW_USE_2} | {FW_SECURITY_2} |

### 3.2 数据库和存储

| 类型 | 技术 | 版本 | 用途 | 加密状态 |
|------|------|------|------|---------|
| 主数据库 | {MAIN_DB} | {MAIN_DB_VER} | {MAIN_DB_USE} | {MAIN_DB_ENC} |
| 缓存 | {CACHE_DB} | {CACHE_DB_VER} | {CACHE_DB_USE} | {CACHE_DB_ENC} |
| 文件存储 | {FILE_STORE} | {FILE_STORE_VER} | {FILE_STORE_USE} | {FILE_STORE_ENC} |

### 3.3 消息队列和缓存

| 组件 | 技术 | 版本 | 配置 | 安全配置 |
|------|------|------|------|---------|
| {MQ_COMPONENT_1} | {MQ_TECH_1} | {MQ_VER_1} | {MQ_CONFIG_1} | {MQ_SECURITY_1} |
| {MQ_COMPONENT_2} | {MQ_TECH_2} | {MQ_VER_2} | {MQ_CONFIG_2} | {MQ_SECURITY_2} |

### 3.4 安全相关组件

| 组件类型 | 库/服务 | 版本 | 配置位置 | 状态 |
|---------|--------|------|---------|------|
| 认证 | {AUTH_LIB} | {AUTH_VER} | `{AUTH_PATH}` | {AUTH_STATUS} |
| 加密 | {CRYPTO_LIB} | {CRYPTO_VER} | `{CRYPTO_PATH}` | {CRYPTO_STATUS} |
| 密钥管理 | {KMS_LIB} | {KMS_VER} | `{KMS_PATH}` | {KMS_STATUS} |
| 日志 | {LOG_LIB} | {LOG_VER} | `{LOG_PATH}` | {LOG_STATUS} |
| 审计 | {AUDIT_LIB} | {AUDIT_VER} | `{AUDIT_PATH}` | {AUDIT_STATUS} |

---

## 4. 安全相关模块

### 4.1 认证模块

**位置**: `{AUTH_MODULE_PATH}`

**实现方式**: {AUTH_IMPLEMENTATION}

**认证机制**:
| 机制 | 实现状态 | 配置 |
|------|---------|------|
| 用户名/密码 | {USERPASS_STATUS} | {USERPASS_CONFIG} |
| OAuth 2.0 | {OAUTH_STATUS} | {OAUTH_CONFIG} |
| SAML | {SAML_STATUS} | {SAML_CONFIG} |
| LDAP | {LDAP_STATUS} | {LDAP_CONFIG} |
| MFA/2FA | {MFA_STATUS} | {MFA_CONFIG} |
| API Key | {APIKEY_STATUS} | {APIKEY_CONFIG} |
| JWT | {JWT_STATUS} | {JWT_CONFIG} |

**关键代码位置**:
{AUTH_CODE_LOCATIONS}
<!--
格式:
- `src/auth/jwt.service.ts:L45-L120` - JWT 签名和验证
- `src/auth/password.ts:L20-L80` - 密码哈希
-->

### 4.2 授权模块

**位置**: `{AUTHZ_MODULE_PATH}`

**实现方式**: {AUTHZ_IMPLEMENTATION}

**权限模型**:
| 模型类型 | 实现状态 | 说明 |
|---------|---------|------|
| RBAC | {RBAC_STATUS} | {RBAC_NOTES} |
| ABAC | {ABAC_STATUS} | {ABAC_NOTES} |
| ACL | {ACL_STATUS} | {ACL_NOTES} |

**关键代码位置**:
{AUTHZ_CODE_LOCATIONS}

### 4.3 加密模块

**位置**: `{CRYPTO_MODULE_PATH}`

**使用的加密算法**:
| 用途 | 算法 | 密钥长度 | 状态 |
|------|------|---------|------|
| 数据加密 | {DATA_ENC_ALG} | {DATA_ENC_KEY} | {DATA_ENC_STATUS} |
| 密码哈希 | {PASS_HASH_ALG} | N/A | {PASS_HASH_STATUS} |
| Token签名 | {TOKEN_SIGN_ALG} | {TOKEN_SIGN_KEY} | {TOKEN_SIGN_STATUS} |
| TLS | {TLS_VERSION} | N/A | {TLS_STATUS} |

**关键代码位置**:
{CRYPTO_CODE_LOCATIONS}

### 4.4 日志和审计模块

**位置**: `{LOG_MODULE_PATH}`

**日志配置**:
| 日志类型 | 实现 | 敏感数据处理 | 存储位置 |
|---------|------|-------------|---------|
| 应用日志 | {APP_LOG_IMPL} | {APP_LOG_SENSITIVE} | {APP_LOG_STORAGE} |
| 安全日志 | {SEC_LOG_IMPL} | {SEC_LOG_SENSITIVE} | {SEC_LOG_STORAGE} |
| 审计日志 | {AUDIT_LOG_IMPL} | {AUDIT_LOG_SENSITIVE} | {AUDIT_LOG_STORAGE} |
| 访问日志 | {ACCESS_LOG_IMPL} | {ACCESS_LOG_SENSITIVE} | {ACCESS_LOG_STORAGE} |

---

## 5. 初始攻击面

### 5.1 外部入口点

| 入口点类型 | 端点/路径 | 认证要求 | 暴露级别 | 风险等级 |
|-----------|---------|---------|---------|---------|
| HTTP API | {API_ENDPOINT_1} | {API_AUTH_1} | {API_EXPOSURE_1} | {API_RISK_1} |
| WebSocket | {WS_ENDPOINT} | {WS_AUTH} | {WS_EXPOSURE} | {WS_RISK} |
| Webhook | {WEBHOOK_ENDPOINT} | {WEBHOOK_AUTH} | {WEBHOOK_EXPOSURE} | {WEBHOOK_RISK} |
| CLI | {CLI_ENDPOINT} | {CLI_AUTH} | {CLI_EXPOSURE} | {CLI_RISK} |

### 5.2 API 端点

| 端点 | 方法 | 认证 | 授权 | 敏感操作 | 安全注意 |
|------|------|------|------|---------|---------|
{API_ENDPOINTS_TABLE}
<!--
格式:
| /api/v1/auth/login | POST | 无 | 无 | 是 | 暴力破解风险 |
| /api/v1/users | GET | JWT | RBAC | 否 | 信息泄露风险 |
-->

### 5.3 敏感数据位置

| 数据类型 | 存储位置 | 加密状态 | 访问控制 | 风险等级 |
|---------|---------|---------|---------|---------|
| 用户凭证 | {CRED_LOCATION} | {CRED_ENC} | {CRED_ACCESS} | {CRED_RISK} |
| API密钥 | {APIKEY_LOCATION} | {APIKEY_ENC} | {APIKEY_ACCESS} | {APIKEY_RISK} |
| PII数据 | {PII_LOCATION} | {PII_ENC} | {PII_ACCESS} | {PII_RISK} |
| 业务敏感 | {BIZ_LOCATION} | {BIZ_ENC} | {BIZ_ACCESS} | {BIZ_RISK} |
| 日志数据 | {LOG_LOCATION} | {LOG_ENC} | {LOG_ACCESS} | {LOG_RISK} |

---

## 6. 安全发现汇总 (Phase 1)

### 6.1 发现统计

| 严重程度 | 数量 | 百分比 |
|---------|------|--------|
| Critical | {SF_CRITICAL} | {SF_CRITICAL_PCT}% |
| High | {SF_HIGH} | {SF_HIGH_PCT}% |
| Medium | {SF_MEDIUM} | {SF_MEDIUM_PCT}% |
| Low | {SF_LOW} | {SF_LOW_PCT}% |
| **总计** | **{SF_TOTAL}** | **100%** |

### 6.2 发现清单

| 发现ID | 类型 | 标题 | 位置 | 严重程度 | 后续阶段 |
|--------|------|------|------|---------|---------|
{SECURITY_FINDINGS_TABLE}

### 6.3 风险指示器

| 指示器描述 | 相关发现 | 建议分析深度 |
|-----------|---------|-------------|
{RISK_INDICATORS_TABLE}

### 6.4 阶段反思

**关键发现**:
{KEY_FINDINGS_LIST}

**需要关注**:
{ATTENTION_AREAS_LIST}

**传递给下阶段**:
{HANDOVER_NOTES_LIST}

---

**报告结束**
