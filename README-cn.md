# STRIDE 深度威胁建模 Skill

**代码优先的自动化威胁建模工具集** | 版本 2.2.1

8阶段串行工作流 · 双知识库架构 · STRIDE+CWE+CAPEC+ATT&CK 全链映射 · LLM原生设计

[安装](#安装) · [快速开始](#快速开始) · [文档](#文档) · [English](README.md)

---

## 概述

一个为 Claude Code 设计的综合性 **Code-First** 威胁建模工具集，通过 8 阶段串行工作流将源代码分析转化为可操作的安全洞察。

### 核心特性

| 特性 | 描述 |
|------|------|
| **8阶段串行工作流** | 严格顺序执行，确保最大深度和完整覆盖 |
| **双知识库** | 核心库 (969 CWE, 615 CAPEC) + CVE扩展 (323K+ CVE) |
| **全链映射** | STRIDE → CWE → CAPEC → ATT&CK → CVE/KEV 威胁情报链 |
| **攻击路径验证** | CAPEC + ATT&CK 攻击链映射 + POC 设计 |
| **KB增强缓解** | 基于知识库的上下文感知缓解建议 |
| **AI/LLM 扩展** | OWASP LLM Top 10 + AI 组件威胁覆盖 |
| **并行子代理支持** | 大型项目多风险并行分析 |
| **语义搜索** | 3,278 个向量用于智能威胁查找 |

### 工作流概览

```
Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► Phase 6 ──► Phase 7 ──► Phase 8
项目理解     调用流/DFD   信任边界     安全设计     STRIDE分析   风险验证     缓解措施     综合报告
```

---

## 安装

### 安装方式选择

```
┌─────────────────────────────────────────────────────────────┐
│                    如何选择安装方式？                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  个人使用，多项目共享  ──────►  全局安装                    │
│                                 ~/.claude/skills/           │
│                                                              │
│  团队协作，需要版本控制 ──────►  项目本地安装               │
│                                 项目/.claude/skills/        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 系统要求

```
Python 3.8+  |  PyYAML >= 6.0
```

### 方式一：全局安装（所有项目可用）

```bash
# 复制到 Claude Code 全局 skills 目录
cp -r threat-modeling ~/.claude/skills/threat-modeling

# 安装依赖
pip install pyyaml
```

### 方式二：项目本地安装（仅当前项目可用）

```bash
# 在项目根目录下创建 .claude/skills 目录
mkdir -p /path/to/your-project/.claude/skills

# 复制 skill 到项目本地
cp -r threat-modeling /path/to/your-project/.claude/skills/threat-modeling

# 安装依赖
pip install pyyaml
```

**安装位置对比**：

| 安装方式 | 路径 | 作用范围 |
|----------|------|----------|
| 全局 | `~/.claude/skills/` | 所有项目 |
| 项目本地 | `项目/.claude/skills/` | 仅当前项目 |

> **推荐**：对于团队共享的安全评估项目，使用项目本地安装，skill 可随项目代码一起版本控制。

### 验证安装

```bash
python scripts/query_kb.py --all-stride --pretty
```

### 目录结构

```
threat-modeling/
├── SKILL.md              # ← Claude Code 入口点 (8阶段工作流)
├── WORKFLOW.md           # 详细工作流模板
├── scripts/              # 工具脚本
│   ├── list_files.py         # Phase 1: 项目结构分析
│   ├── stride_matrix.py      # Phase 5: STRIDE 矩阵
│   └── unified_kb_query.py   # Phase 5/6/7: 统一KB查询
└── assets/knowledge/            # 双数据库知识体系 (317MB)
    ├── security_kb.sqlite        # 核心库 (13MB)
    └── security_kb_extension.sqlite  # CVE扩展 (304MB)
```

---

## 快速开始

### 在 Claude Code 中使用

#### 自动激活

说出以下任意关键词，skill 将自动激活：

| 中文 | English |
|------|---------|
| 威胁建模 | threat model |
| 安全评估 | security assessment |
| 数据流图 | DFD / data flow diagram |
| 信任边界 | trust boundary |
| 攻击面 | attack surface |
| STRIDE 分析 | STRIDE analysis |

#### 使用示例

**威胁建模**
```
用户: 帮我对 @/path/to/project 进行威胁建模

Claude: [自动激活 skill]
        Phase 1: 分析项目结构...
        Phase 2: 构建 DFD...
        Phase 5: STRIDE 分析...

        ## 威胁清单
        | ID | 类别 | 描述 | 优先级 |
        | T-S-P001-001 | Spoofing | API 缺少认证 | Critical |
        ...
```

**快速安全检查**
```
用户: 快速检查这个服务的安全问题 @/path/to/service

Claude: 发现 3 个高危威胁：
        - T-S-P001-001: API 端点缺少认证
        - T-E-P002-001: 删除接口缺少授权检查
        - T-I-DF001-001: 敏感数据明文传输
```

**AI/LLM 应用**
```
用户: 分析这个 RAG 应用的安全风险 @/path/to/rag-app

Claude: [启用 OWASP LLM Top 10 扩展]
        - LLM01: Prompt Injection 风险
        - LLM06: 敏感信息泄露风险
        ...
```

### 手动执行脚本

```bash
# 项目结构分析 (Phase 1)
python scripts/list_files.py ./project --categorize --detect-type --pretty

# 知识库查询 (Phase 5/6/7)
python scripts/unified_kb_query.py --full-chain CWE-89
python scripts/unified_kb_query.py --capec CAPEC-66 --attack-chain
python scripts/unified_kb_query.py --attack-technique T1059
python scripts/unified_kb_query.py --cwe CWE-89 --mitigations
python scripts/unified_kb_query.py --all-llm
```

---

## 核心能力

### 8阶段工作流输出

| 阶段 | 输出 |
|------|------|
| **1-4** | 项目概要、DFD图、关键接口/边界/数据节点、安全设计矩阵 |
| **5** | 威胁清单 (STRIDE+CWE+ATT&CK+LLM) |
| **6** | **验证方式** (攻击路径 + POC) |
| **7** | **缓解措施** (每条风险的缓解建议) |
| **8** | `THREAT-MODEL-REPORT.md` 综合报告 |

### 能力矩阵

| 能力 | 描述 |
|------|------|
| 8阶段串行工作流 | 严格顺序执行，每阶段输出传递至下阶段 |
| DFD 构建 | Mermaid 模板 + 元素清单 + 信任边界 |
| STRIDE 矩阵 | TMT 兼容的 STRIDE per Interaction |
| 威胁 ID | 标准格式 `T-{STRIDE}-{Element}-{Seq}` |
| 双数据库知识库 | 核心库 (969 CWE, 615 CAPEC) + CVE扩展 (323K+ CVE) |
| 攻击路径验证 | CAPEC + ATT&CK 攻击链映射 + POC 设计 |
| KB增强缓解 | 每条风险查询知识库生成定制化缓解措施 |

### 场景扩展

| 扩展 | 覆盖 |
|------|------|
| **云服务** | AWS / Azure / GCP / 阿里云 / 腾讯云 |
| **AI/LLM** | OWASP LLM Top 10 + AI 组件威胁 |
| **CVE验证** | 323K+ CVE + KEV (已知被利用漏洞) 检查 |

---

## 文档

| 文档 | 内容 |
|------|------|
| **[SKILL.md](SKILL.md)** | Claude Code skill 入口点 (8阶段工作流概览) |
| **[WORKFLOW.md](WORKFLOW.md)** | 详细 8 阶段深度工作流模板 |
| **[GUIDE-cn.md](GUIDE-cn.md)** | 设计理念、脚本参考、知识库架构、故障排除 |
| **[EXAMPLES-cn.md](EXAMPLES-cn.md)** | 5 个真实案例（REST API、微服务、AI/LLM、云原生） |

### 架构文档

| 文档 | 内容 |
|------|------|
| **[references/KNOWLEDGE-ARCHITECTURE-v5.2-cn.md](references/KNOWLEDGE-ARCHITECTURE-v5.2-cn.md)** | 知识库架构 (双体系 A+B) |
| **[references/COMPREHENSIVE-ARCHITECTURE-WORKFLOW-GUIDE-cn.md](references/COMPREHENSIVE-ARCHITECTURE-WORKFLOW-GUIDE-cn.md)** | 完整架构与工作流指南 |

---

## 知识架构

### 双知识体系

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              双知识体系架构                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  体系 A: 安全控制层级                         体系 B: 威胁情报层级          │
│  ─────────────────────                       ─────────────────────          │
│  L1: ASVS 控制要求                           L1: STRIDE 威胁分类            │
│  L2: 安全实现模式                            L2: CWE+CAPEC+ATT&CK 映射      │
│  L3: 验证测试用例                            L3: CVE 漏洞数据库             │
│                                              L4: KEV 实时情报               │
│                                                                              │
│  验证集: WSTG(121) + MASTG(206) + ASVS(345) = 672 测试                     │
│  → 映射到 1,269 个 STRIDE+测试 组合                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 威胁情报链

```
STRIDE → CWE → CAPEC → ATT&CK → CVE/KEV
  L1      ├────── L2 ──────┤    L3 + L4

L1 STRIDE → L2 威胁情报映射:
───────────────────────────────────────────────────────────────────────────────
S(身份伪造)   → CWE-287/290/307 → CAPEC-151/194/600 → T1078/T1110 → CVE-*
T(数据篡改)   → CWE-20/77/89    → CAPEC-66/88/248   → T1190/T1059 → CVE-*
R(抵赖)       → CWE-117/223/778 → CAPEC-93/268      → T1070/T1562 → CVE-*
I(信息泄露)   → CWE-200/209/311 → CAPEC-116/157/497 → T1552/T1213 → CVE-*
D(拒绝服务)   → CWE-400/770/918 → CAPEC-125/227/469 → T1498/T1499 → CVE-*
E(权限提升)   → CWE-269/284/862 → CAPEC-122/233/17  → T1068/T1548 → CVE-*
```

---

## LLM 兼容性

### 设计原则

本 skill 遵循 **LLM 原生设计** 原则，确保广泛兼容：

| 原则 | 描述 |
|------|------|
| **上下文而非控制** | 知识库赋能 LLM 智能，而非限制它 |
| **LLM 自主性** | KB 提供上下文；LLM 执行语义推理 |
| **脚本黑盒化** | 脚本处理确定性操作；LLM 处理分析 |
| **双轨知识** | 安全控制（防御）+ 威胁模式（攻击）|

### Agent 架构

支持 Phase 5/6/7 的并行子代理模式：

```
主代理 ──► 风险 1 ──► 子代理 1 ──► KB 查询 ──► 结果 1
       ──► 风险 2 ──► 子代理 2 ──► KB 查询 ──► 结果 2
       ──► 风险 N ──► 子代理 N ──► KB 查询 ──► 结果 N
                                       │
       ◄─────────── 聚合结果 ──────────┘
```

**规模阈值**：
| 项目规模 | 文件数 | 策略 |
|---------|-------|------|
| 小型 | <50 | 标准 8 阶段 |
| 中型 | 50-200 | 模块优先分析 |
| 大型 | 200-500 | 子系统拆分+合并 |
| 超大型 | >500 | 并行子代理 |

---

## 版本历史

### v2.2.1 (当前版本)

- **Phase 2 DFD/CFD 知识库增强**: 添加 4 个 YAML 模式文件用于改进 DFD/CFD 分析
  - `framework-routing-patterns.yaml`: 框架路由检测（Express、FastAPI、Spring、AI/LLM 框架）
  - `data-store-patterns.yaml`: 数据存储识别模式
  - `security-checkpoint-patterns.yaml`: 安全检查点检测模式
  - `completeness-rules.yaml`: Phase 2 输出完整性验证规则
- **MCP 架构与 LLM 安全检测**: 增强 MCP Server 模式和 Agent 架构威胁检测
- **Claude Code 生态集成**: 改进对 hooks、MCP servers、slash commands 的支持
- **Session 版本控制**: 工作流阶段可追溯性和版本管理改进
- **测试覆盖率提升**: `unified_kb_query.py` 覆盖率提升至 53%（目标 ≥80%）

### v2.1.3

- **STRIDE 名称到代码映射修复**: `get_cwes_for_stride_sqlite()` 现在同时支持全名（"spoofing"）和代码（"S"）
- **FTS5 索引重建**: 所有 12 个全文搜索索引已重建并验证
- **E2E 接口测试**: 为 UnifiedKnowledgeBase 添加了 25 项综合测试套件
- **LLM 兼容性文档**: 添加了设计原则和代理架构章节
- **语义向量**: 3,278 个条目用于智能威胁查找

### v2.1.2

- **ATT&CK 战术解析修复**: 将 `json.loads()` 改为 `str.split(',')` 处理逗号分隔字段
- **FTS 异常处理**: 为损坏的 FTS 索引添加 `sqlite3.DatabaseError` 捕获

### v2.1.1

- **ATT&CK JSON 解析修复**: 修正战术和平台字段解析
- **删除过时测试脚本**: 删除了引用不存在数据库的脚本

### v2.1.0

- **目录结构重构**: 重组为 `references/`、`assets/knowledge/`、`assets/schemas/`、`assets/templates/`

### v2.0.0

- **STRIDE→测试映射扩展**: 162 → 1,269 测试映射
- **验证集集成**: WSTG(121) + MASTG(206) + ASVS(345)
- **双知识架构**: 体系 A (控制) + 体系 B (威胁)
- **双语文档**: 完整英文 + 中文文档

完整版本历史请参阅 [CHANGELOG.md](CHANGELOG.md)。

---

**版本 2.2.1** | [完整文档](GUIDE-cn.md) | [更新日志](CHANGELOG.md) | [English](README.md)
