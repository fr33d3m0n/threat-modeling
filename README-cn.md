<!-- Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | 欢迎引用但请保留所有来源及声明 -->

# Code-First Deep Risk Analysis Skill

**代码优先的自动化威胁建模工具集** | 版本 2.1.0

8阶段串行工作流 · 双知识库架构 · STRIDE+CWE+CAPEC+ATT&CK 全链映射

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
| **安全设计与控制** | 11项安全原则 + 16个安全域评估与控制映射 |
| **攻击路径验证** | CAPEC + ATT&CK 攻击链映射 + POC 设计 |
| **KB增强缓解** | 基于知识库的上下文感知缓解建议 |
| **AI/LLM 扩展** | OWASP LLM Top 10 + AI 组件威胁覆盖 |
| **Agent Skill Prompt 评估** | OWASP Agentic Top 10 (ASI01-ASI10) + 最小代理原则评估 |

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
| 安全检查 | security check |
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
        | T-S-P1-001 | Spoofing | API 缺少认证 | Critical |
        ...
```

**快速安全检查**
```
用户: 快速检查这个服务的安全问题 @/path/to/service

Claude: 发现 3 个高危威胁：
        - T-S-P1-001: API 端点缺少认证
        - T-E-P2-001: 删除接口缺少授权检查
        - T-I-DF1-001: 敏感数据明文传输
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
| **8** | `{PROJECT}-RISK-ASSESSMENT-REPORT.md` 综合报告 |

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
| **Agent/Skill Prompt** | OWASP Agentic Security Top 10 + 最小代理原则 |

### Agent & Skill Prompt 安全评估

针对 AI Agent 系统和 Claude Code Skills 的专项安全评估：

| 评估领域 | 覆盖内容 |
|----------|----------|
| **OWASP Agentic Top 10** | ASI01-ASI10 自主 AI Agent 漏洞类别 |
| **最小代理原则** | 最小权限与能力范围评估 |
| **工具调用安全** | MCP 服务器集成、命令注入、路径遍历 |
| **Prompt 注入防御** | 直接/间接注入、越狱抵抗分析 |
| **数据边界控制** | 敏感数据暴露、上下文泄漏防护 |
| **自主性风险评估** | 决策边界、人工监督、操作可逆性 |

---

## 文档

| 文档 | 内容 |
|------|------|
| **[SKILL.md](SKILL.md)** | Claude Code skill 入口点 (8阶段工作流概览) |
| **[WORKFLOW.md](WORKFLOW.md)** | 详细 8 阶段深度工作流模板 |
| **[README-cn.md](README-cn.md)** | 快速入门指南、安装说明、使用示例 |
| **[EXAMPLES-cn.md](EXAMPLES-cn.md)** | 5 个真实案例（REST API、微服务、AI/LLM、云原生） |

### 架构文档

| 文档 | 内容 |
|------|------|
| **[references/SKILL-ARCHITECTURE-DESIGN-cn.md](references/SKILL-ARCHITECTURE-DESIGN-cn.md)** | 系统架构与设计原则 |
| **[references/ARCHITECTURE-WORKFLOW-GUIDE-cn.md](references/ARCHITECTURE-WORKFLOW-GUIDE-cn.md)** | 完整架构与工作流指南 |
| **[references/KNOWLEDGE-ARCHITECTURE-v5.2-cn.md](references/KNOWLEDGE-ARCHITECTURE-v5.2-cn.md)** | 知识库架构 (双体系 A+B) |

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
│  L1: 安全原则 (11) +                         L1: STRIDE 威胁分类            │
│      安全域 (16)                             L2: CWE+CAPEC+ATT&CK 映射      │
│  L2: 控制集 + OWASP 参考                     L3: CVE 漏洞数据库             │
│  L3: 合规框架                                L4: KEV 实时情报               │
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

## 版本历史

### v2.1.0 (当前版本)

- **STRIDE→测试映射扩展**: 162 → 1,269 测试映射
- **验证集集成**: WSTG(121) + MASTG(206) + ASVS(345)
- **L1 STRIDE 层**: 完整威胁情报链文档
- **双知识架构**: 体系 A (控制) + 体系 B (威胁)
- **双语文档**: 完整英文 + 中文文档

---

**版本 2.1.0** | [English](README.md)
