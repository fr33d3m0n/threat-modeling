<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations -->

# Security Knowledge Base

威胁建模安全知识库 - 支持 STRIDE 分析、多层知识链和语义搜索。

## 知识体系概览 (SUKA v4.0)

```
四层安全知识架构 (Four-Level Security Knowledge Hierarchy)
═════════════════════════════════════════════════════════════════════════════

L1: Security Principles (安全原则)
├── SKILL.md                     # 10个核心安全原则 (DID, LP, ZT, FS, SOD, SBD, CM, EOM, OD, IV)
└── 指导 L2-L4 的设计与实现

L2: Security Design (安全设计域) - security-design.yaml v4.0
├── 核心域 (01-10): AUTHN, AUTHZ, INPUT, OUTPUT, CLIENT, CRYPTO, LOG, ERROR, API, DATA
└── 扩展域 (ext-11 to ext-15): INFRA, SUPPLY, AI, MOBILE, CLOUD

L3: Security Controls (安全控制集) - 17个文件
├── 核心控制: control-set-{01-10}-*.md
├── 跨域扩展: control-set-ext-{NN}_{MM}-*.md (如 ext-01_02-auth-patterns)
├── 域内扩展: control-set-ext-{NN}-*.md (如 ext-10-hardcoded-credentials)
└── 扩展域控制: control-set-ext-{11-15}-*.md

L4: Scenario Practices (场景实践) - 73个OWASP参考文件
├── 核心引用: reference-set-{01-10}-*.md
└── 扩展引用: reference-set-ext-{11-15}-*.md
```

## 5层知识架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Layer 5: Live Vulnerability Data (Optional NVD API fallback)          │
│  ─────────────────────────────────────────────────────────────────────  │
│  CVE实时查询 | NVD API | 当本地扩展库不可用时的降级方案               │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 4: Compliance Framework Knowledge                                │
│  ─────────────────────────────────────────────────────────────────────  │
│  NIST 800-53 | CIS Controls | CSA CCM | ISO 27001/27017/42001          │
│  14个合规框架 → STRIDE映射 | 控制措施 | 合规差距分析                  │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 3: Security Verification Knowledge                               │
│  ─────────────────────────────────────────────────────────────────────  │
│  WSTG Tests | MASTG Tests | ASVS Requirements                          │
│  验证测试用例 | CWE映射 | 工具推荐 | 自动化检测方法                   │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 2: Security Controls & Implementation Patterns                   │
│  ─────────────────────────────────────────────────────────────────────  │
│  认证模式 | 授权控制 | 输入验证 | 加密实现 | 日志审计                  │
│  17个安全控制集 → STRIDE缓解 | 代码示例 | 检查清单                    │
├─────────────────────────────────────────────────────────────────────────┤
│  Layer 1: Core Threat Intelligence                                      │
│  ─────────────────────────────────────────────────────────────────────  │
│  STRIDE → OWASP → CWE → CAPEC → ATT&CK                                 │
│  威胁分类 | 弱点定义 | 攻击模式 | 攻击技术                             │
└─────────────────────────────────────────────────────────────────────────┘
```

## 目录结构

```
knowledge/
├── README.md                        # 本文档
├── __init__.py                      # Python模块接口
│
├── security_kb.sqlite               # Core数据库 (14MB, 必需)
├── security_kb_extension.sqlite     # CVE扩展库 (304MB, 可选)
│
├── security-design.yaml             # L2: 安全设计域配置 (v4.0)
│
├── security-controls/               # L3: 安全控制集 (17文件)
│   │
│   │  # Core Domains (01-10)
│   ├── control-set-01-authentication.md           # AUTHN 认证与会话
│   ├── control-set-02-authorization.md            # AUTHZ 授权控制
│   ├── control-set-03-input-validation.md         # INPUT 输入验证
│   ├── control-set-04-output-encoding.md          # OUTPUT 输出编码 (NEW)
│   ├── control-set-05-client-side.md              # CLIENT 客户端安全
│   ├── control-set-06-cryptography.md             # CRYPTO 加密传输
│   ├── control-set-07-logging.md                  # LOG 日志审计
│   ├── control-set-08-error-handling.md           # ERROR 错误处理
│   ├── control-set-09-api-security.md             # API 服务安全
│   ├── control-set-10-data-protection.md          # DATA 数据保护
│   │
│   │  # Domain Extensions
│   ├── control-set-ext-01_02-auth-patterns.md     # AUTHN+AUTHZ 跨域模式
│   ├── control-set-ext-10-hardcoded-credentials.md # DATA 凭证管理扩展
│   │
│   │  # Extended Domains (ext-11 to ext-15)
│   ├── control-set-ext-11-infrastructure.md       # INFRA 基础设施
│   ├── control-set-ext-12-supply-chain.md         # SUPPLY 供应链
│   ├── control-set-ext-13-ai-llm.md               # AI/LLM 安全
│   ├── control-set-ext-14-mobile.md               # MOBILE 移动端
│   ├── control-set-ext-15-cloud.md                # CLOUD 云安全
│   │
│   └── references/                  # L4: OWASP场景实践 (73文件)
│       │
│       │  # Core Domain References (01-10)
│       ├── reference-set-01-*.md    # AUTHN 认证 (11文件)
│       ├── reference-set-02-*.md    # AUTHZ 授权 (4文件)
│       ├── reference-set-03-*.md    # INPUT 输入 (13文件)
│       ├── reference-set-05-*.md    # CLIENT 客户端 (13文件)
│       ├── reference-set-06-*.md    # CRYPTO 加密 (6文件)
│       ├── reference-set-07-*.md    # LOG 日志 (2文件)
│       ├── reference-set-08-*.md    # ERROR 错误 (2文件)
│       ├── reference-set-09-*.md    # API 服务 (7文件)
│       ├── reference-set-10-*.md    # DATA 数据 (3文件)
│       │
│       │  # Extended Domain References (ext-11 to ext-15)
│       ├── reference-set-ext-11-*.md # INFRA (4文件)
│       ├── reference-set-ext-12-*.md # SUPPLY (4文件)
│       ├── reference-set-ext-13-*.md # AI (1文件)
│       ├── reference-set-ext-14-*.md # MOBILE (2文件)
│       └── reference-set-ext-15-*.md # CLOUD (1文件)
│
├── stride-library.yaml              # STRIDE威胁库
├── stride-controls-mapping.yaml     # STRIDE→控制映射
├── cwe-mappings.yaml                # CWE Top 25映射
├── capec-mappings.yaml              # CAPEC攻击模式
├── comprehensive-mappings.yaml      # 综合映射表
├── stride_cwe_mapping.json          # STRIDE→CWE JSON
├── owasp_cwe_mapping.json           # OWASP→CWE JSON
│
├── cloud-services.yaml              # 云服务安全配置
├── llm-threats.yaml                 # LLM/AI特定威胁
│
└── schema-extension-design.sql      # 数据库扩展设计
```

## 数据库架构

### Core 数据库 (security_kb.sqlite)

| Layer | 表名 | 记录数 | 说明 |
|-------|------|--------|------|
| **Layer 1** | stride_category | 6 | STRIDE威胁类别 |
| | stride_cwe | 403 | STRIDE→CWE映射 |
| | cwe | 974 | CWE弱点定义 |
| | capec | 615 | CAPEC攻击模式 |
| | attack_technique | 835 | MITRE ATT&CK技术 |
| | attack_mitigation | 43 | ATT&CK缓解措施 |
| | owasp_top10 | 10 | OWASP Top 10 2025 |
| | owasp_cwe | 248 | OWASP→CWE映射 |
| **Layer 2** | security_control | 16 | 安全控制模式 |
| | stride_security_control | 37 | STRIDE→控制映射 |
| **Layer 3** | wstg_test | 121 | WSTG 4.2测试用例 |
| | mastg_test | 206 | MASTG 2.0测试用例 |
| | asvs_requirement | 345 | ASVS 5.0验证要求 |
| | stride_verification | 162 | STRIDE→测试映射 |
| | cwe_verification | 12,035 | CWE→测试映射 ✅ |
| **Layer 4** | compliance_framework | 14 | 合规框架定义 |
| | compliance_control | 115 | 控制措施详情 |
| | stride_compliance | 51 | STRIDE→合规映射 |
| | cwe_compliance | 3,534 | CWE→合规映射 ✅ |
| | owasp_compliance | 0* | OWASP→合规映射 |
| | ai_compliance_requirement | 0* | AI合规要求 |
| **Embeddings** | kb_embeddings | 3,278 | 语义搜索向量 (384维) |
| **Search** | query_cache | - | 查询缓存表 (新增) |

> *标记为0的表保留待扩展。

### Extension 数据库 (security_kb_extension.sqlite)

| 表 | 记录数 | 说明 |
|---|--------|------|
| cve | 323,830 | NVD CVE索引 |
| cve_cwe | 108,409 | CVE→CWE映射 |

## 功能特性

### 1. 完整知识链

```
STRIDE威胁 → OWASP类别 → CWE弱点 → CAPEC攻击 → ATT&CK技术 → CVE漏洞
    ↓            ↓           ↓          ↓            ↓          ↓
  6类别      10类别      248个      659个       206+技术    323K+
    ↓
安全控制 ←─────────────────────────────────────────────────────┘
    ↓
验证测试 (WSTG/MASTG/ASVS)
    ↓
合规控制 (NIST/CIS/CSA/ISO)
```

### 2. 语义搜索

使用预计算的384维向量实现语义相似度搜索：

```python
from unified_kb_query import UnifiedKnowledgeBase

kb = UnifiedKnowledgeBase()
results = kb.semantic_search("SQL injection attack", limit=5)
# → CAPEC-66: SQL Injection (score: 0.72)
```

### 3. 多层查询

```python
# STRIDE → 验证测试
tests = kb.get_verification_tests_for_stride("T")  # Tampering

# STRIDE → 合规控制
controls = kb.get_compliance_controls_for_stride("S")  # Spoofing

# STRIDE → 安全控制模式
patterns = kb.get_security_controls_for_stride("E")  # Elevation
```

### 4. 优雅降级

- 有embedding模型 → 向量相似度搜索
- 无embedding模型 → 自动回退FTS5全文搜索
- 无Extension库 → CVE查询返回友好提示
- 无NVD API → 使用本地CVE扩展库

## 使用方法

### Python API

```python
from unified_kb_query import UnifiedKnowledgeBase

kb = UnifiedKnowledgeBase()

# 检查能力
print(f"Embeddings: {kb.has_embeddings}")  # True
print(f"CVE Extension: {kb.has_extension}") # True/False

# CWE查询
cwe = kb.get_sqlite_cwe("CWE-89")

# STRIDE分析
cwes = kb.get_cwes_for_stride_sqlite("S")  # Spoofing

# 语义搜索
results = kb.semantic_search("authentication bypass",
                             entry_types=["cwe", "capec"])

# CVE查询 (需要Extension)
if kb.has_extension:
    cve = kb.get_cve("CVE-2021-44228")
```

### 命令行

```bash
# STRIDE查询
python scripts/unified_kb_query.py --stride spoofing

# CWE完整链
python scripts/unified_kb_query.py --cwe CWE-89 --full-chain

# 统计信息
python scripts/unified_kb_query.py --stats
```

## 数据来源

| Layer | 数据 | 来源 | 版本 |
|-------|------|------|------|
| 1 | CWE | MITRE CWE | 4.19 |
| 1 | CAPEC | MITRE CAPEC | 3.9 |
| 1 | ATT&CK | MITRE ATT&CK | 18.1 |
| 1 | OWASP | OWASP Top 10 | 2025 |
| 2 | Security Controls | Curated Patterns | 1.0 |
| 3 | WSTG | OWASP WSTG | 4.2 |
| 3 | MASTG | OWASP MASTG | 2.0 |
| 3 | ASVS | OWASP ASVS | 5.0 |
| 4 | Compliance | NIST/CIS/CSA/ISO | 2024 |
| 5 | CVE | NVD | 2025-12 |

## 技术规格

### Embedding

- 模型: `all-MiniLM-L6-v2`
- 维度: 384
- 格式: float32 BLOB
- 大小: ~4.8 MB (3,273条)

### 索引

- FTS5全文索引: CWE, CAPEC, ATT&CK, WSTG, MASTG, ASVS, Compliance
- B-tree索引: 所有主键和外键

### 数据库大小

| 文件 | 大小 | 必需 |
|------|------|------|
| security_kb.sqlite | ~14MB | 是 |
| security_kb_extension.sqlite | ~304MB | 否 |

## 更新日志

- **2025-12-30**: SUKA v4.0: 严格域序列 + 扩展命名规范
  - OUTPUT/CLIENT 域分离: OUTPUT(04)输出编码, CLIENT(05)客户端安全
  - 严格域序列: 01-10核心域, ext-11到ext-15扩展域
  - 跨域扩展命名: `control-set-ext-{NN}_{MM}-*.md` (如 ext-01_02-auth-patterns)
  - 域内扩展命名: `control-set-ext-{NN}-*.md` (如 ext-10-hardcoded-credentials)
  - 扩展域命名: `control-set-ext-{11-15}-*.md`
  - 总计17个L3控制集文件, 73个L4参考文件
- **2025-12-30**: SUKA v3.2: 四层知识架构统一 (已升级到v4.0)
- **2025-12-26**: L1-L5完成: 知识库优化增强
  - L1: CWE embedding补全 (活跃CWE 100%覆盖)
  - L2: FTS5索引扩展 (12个虚拟表)
  - L3: CWE知识链映射 (12,035验证 + 3,534合规)
  - L4: 搜索优化 (hybrid search, query cache)
- **2025-12-26**: M4完成: R/D/E安全控制扩展 (16控制, 37映射)
- **2025-12-26**: M1-M3完成: 合规框架扩展 (115控制, 51映射, CIS/NIST-CSF/AI)
- **2025-12-26**: OWASP Top 10 2025 完整数据更新 (248 CWE映射, 全类别描述)
- **2025-12-26**: Layer 3 完成: ASVS 5.0 (345), WSTG 4.2 (121), MASTG 2.0 (206)
- **2025-12-26**: STRIDE→验证测试映射扩展 (162条)
- **2025-12-26**: Layer 2 Security Controls 集成
- **2025-12-24**: 向量搜索支持，双数据库架构
- **2025-12-24**: CVE索引323K条
- **2025-12-24**: V2架构迁移完成
