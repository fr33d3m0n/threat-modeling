<!-- Threat Modeling Skill | Version 3.0.0 (20260201a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Control Set 17: Agentic Security (AGENT)

**Domain**: AGENT - Agent系统与类Agent组件安全
**Version**: 1.0
**Last Updated**: 2026-01-03
**Reference**: OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10)

---

## Overview

Agentic Security 控制集，适用于完整 AI Agent 系统和类 Agent 组件（Tools, Prompts, Skills）。本控制集关注 Agent 的**行为、意图和自主性**安全，与 ext-13 (AI/LLM Security) 形成互补关系：

- **ext-13**: 聚焦 LLM 模型层面的输入/输出安全
- **ext-16**: 聚焦 Agent 行为层面的自主性和协作安全

**核心安全范式**: Least-Agency Principle (最小自主性原则)
> "Avoid giving agents unnecessary autonomy, not just unnecessary privileges." — OWASP ASI

---

## Trigger Conditions (按需加载)

当检测到以下条件时自动加载本控制集：

### 完整 Agent 系统
- `langchain` / `langgraph` import
- `crewai` / `autogen` / `autogpt` import
- `anthropic.Agent` / `openai.Assistant` API 调用
- Agent workflow 定义文件 (`agent.yaml`, `crew.yaml`)

### 类 Agent 组件
- MCP Server 配置 (`mcp.json`, `claude_desktop_config.json`)
- Tool/Function 定义 (`tools/*.py`, `functions/*.ts`)
- Skill 定义 (`.claude/skills/`, `skills/*.md`)
- Prompt 模板库 (`prompts/*.yaml`, `prompt_templates/`)
- Custom Instructions 配置

### 多 Agent 系统
- A2A (Agent-to-Agent) 协议配置
- Agent 编排框架 (Temporal workflows, Prefect flows)
- Multi-agent communication channels

---

## Core Controls

### AGENT-01: Goal & Intent Protection (目标与意图保护)
**控制要求**: Agent 的目标和意图必须受到保护，防止篡改和劫持

**适用范围**: Agent 系统、Prompt 模板、Skill 定义

**控制措施**:
- **目标完整性验证**
  - System prompt 完整性校验 (hash/签名)
  - 目标定义不可被用户输入覆盖
  - 使用结构化目标定义而非自由文本

- **意图对齐监控**
  - 输出与预期目标的一致性检测
  - 行为偏离告警机制
  - 意图推理日志记录

- **目标篡改检测**
  - 检测试图修改 Agent 目标的提示词
  - 多轮对话中的目标漂移检测
  - 间接目标注入（通过工具返回值）检测

**交叉引用**: 与 ext-13 AI-01 (Prompt Injection Prevention) 互补

**OWASP ASI 映射**: ASI01 - Agent Goal Hijack

---

### AGENT-02: Tool & Skill Governance (工具与技能治理)
**控制要求**: Agent 可使用的工具和技能必须受控、可审计、最小化

**适用范围**: MCP Tools, Function Calling, Skills, Plugins

**控制措施**:
- **工具注册与验证**
  - 工具来源验证和签名校验
  - 工具能力声明审核
  - 版本管理和变更追踪
  - 禁止动态加载未审核工具

- **能力边界限制**
  - 工具权限白名单机制
  - 资源访问范围限制 (文件路径、网络、API)
  - 操作类型限制 (读/写/执行/删除)
  - 调用频率和配额限制

- **工具调用链审计**
  - 完整的调用链日志
  - 工具参数记录（脱敏）
  - 调用结果记录
  - 异常调用模式检测

- **MCP Server 安全**
  - MCP Server 来源验证
  - 最小权限配置
  - 通信加密 (stdio/SSE)
  - Server 隔离执行

**交叉引用**: 与 ext-13 AI-05 (Agent Action Control), ext-12 SUPPLY-04 (Source Verification) 互补

**OWASP ASI 映射**: ASI02 - Tool Misuse & Exploitation, ASI04 - Agentic Supply Chain

---

### AGENT-03: Non-Human Identity (NHI) Management (非人类身份管理)
**控制要求**: Agent 及其组件的身份必须明确、可追踪、权限受控

**适用范围**: Agent 服务账户、API 凭证、委托链

**控制措施**:
- **Agent 身份认证**
  - 唯一 Agent 标识符
  - Agent 凭证安全存储
  - 凭证自动轮换
  - 多因素认证（高风险操作）

- **委托链验证 (Delegation Chain)**
  - 用户 → Agent → Tool 的完整授权链
  - 委托范围限制
  - 委托时效控制
  - 委托链审计日志

- **服务账户最小权限**
  - Agent 专用服务账户
  - 按功能分离权限
  - 禁止共享凭证
  - 定期权限审查

- **身份生命周期管理**
  - Agent 实例创建/销毁记录
  - 凭证生命周期管理
  - 权限变更审计
  - 僵尸 Agent 检测和清理

**交叉引用**: 与 ext-15 CLOUD-01 (IAM Least Privilege), Control-01 (Authentication) 互补

**OWASP ASI 映射**: ASI03 - Identity & Privilege Abuse

---

### AGENT-04: Memory & Context Security (记忆与上下文安全)
**控制要求**: Agent 的持久化记忆和上下文必须受到保护，防止污染和泄露

**适用范围**: Agent Memory, Context Window, Session State, RAG

**控制措施**:
- **持久化记忆保护**
  - 记忆存储加密
  - 记忆访问控制
  - 记忆内容分类（敏感/普通）
  - 记忆版本控制和回滚

- **上下文污染检测**
  - 检测恶意注入的历史消息
  - 上下文完整性校验
  - 异常上下文模式告警
  - 会话历史审计

- **会话隔离**
  - 用户间会话严格隔离
  - Agent 实例间上下文隔离
  - 租户级数据隔离
  - 跨会话信息泄露防护

- **记忆清理策略**
  - 敏感数据自动过期
  - 用户请求删除能力
  - 定期记忆审查
  - 合规性数据保留

**交叉引用**: 与 ext-13 AI-04 (Data Isolation), Control-10 (Data Protection) 互补

**OWASP ASI 映射**: ASI06 - Memory & Context Poisoning

---

### AGENT-05: Multi-Agent Communication Security (多Agent通信安全)
**控制要求**: Agent 间通信必须安全、可验证、边界受控

**适用范围**: Multi-Agent 系统, A2A 协议, Agent 编排

**控制措施**:
- **A2A 协议安全**
  - Agent 间通信加密
  - 消息认证和完整性
  - 防重放攻击
  - 协议版本兼容性验证

- **Agent 间信任验证**
  - Agent 身份互认证
  - 信任级别分层
  - 信任传递规则
  - 恶意 Agent 检测

- **消息内容安全**
  - 消息格式验证
  - 敏感数据脱敏
  - 消息大小限制
  - 恶意载荷检测

- **协作边界控制**
  - Agent 协作范围限制
  - 跨 Agent 数据流控制
  - 协作模式白名单
  - 协作行为审计

**交叉引用**: 与 Control-09 (API Security), ext-11 INFRA-04 (Network Segmentation) 互补

**OWASP ASI 映射**: ASI07 - Insecure Inter-Agent Communication

---

### AGENT-06: Behavioral Monitoring & Alignment (行为监控与对齐)
**控制要求**: Agent 行为必须持续监控，确保与预期目标对齐

**适用范围**: 所有 Agent 系统和类 Agent 组件

**控制措施**:
- **行为偏离检测**
  - 预期行为基线建立
  - 实时行为偏离分析
  - 异常行为模式识别
  - 行为漂移趋势监控

- **自主性边界控制**
  - 自主决策范围限制
  - 高风险决策人工确认
  - 自主性级别动态调整
  - 紧急情况自主性降级

- **行为审计日志**
  - 完整决策过程记录
  - 推理链路追踪
  - 行为归因分析
  - 不可篡改审计日志

- **Rogue Agent 检测**
  - 恶意行为模式库
  - 行为一致性检测
  - 目标背离告警
  - 自动隔离机制

**交叉引用**: 与 Control-07 (Logging), ext-13 AI-05 (Agent Action Control) 互补

**OWASP ASI 映射**: ASI10 - Rogue Agents

---

### AGENT-07: Cascading Failure Prevention (级联故障预防)
**控制要求**: Agent 系统必须具备故障隔离和降级能力，防止故障级联传播

**适用范围**: Multi-Agent 编排, Agent 工作流, Tool 调用链

**控制措施**:
- **故障隔离**
  - Agent 实例级隔离
  - 工具调用失败隔离
  - 错误边界设置
  - 故障域划分

- **错误传播阻断**
  - 错误类型分类处理
  - 错误传播链路切断
  - 毒化输入检测
  - 级联触发检测

- **降级与熔断**
  - 服务降级策略
  - 熔断器模式实现
  - 优雅降级路径
  - 降级状态监控

- **编排层容错**
  - 工作流重试策略
  - 补偿事务机制
  - 超时控制
  - 死锁检测和恢复

**交叉引用**: 与 Control-08 (Error Handling), ext-11 INFRA-03 (Resource Limits) 互补

**OWASP ASI 映射**: ASI08 - Cascading Failures

---

### AGENT-08: Human-Agent Trust Boundary (人机信任边界)
**控制要求**: 必须建立清晰的人机信任边界，高风险操作需人工确认

**适用范围**: 所有 Agent 系统

**控制措施**:
- **Human-in-the-Loop (HITL)**
  - 高风险操作必须人工确认
  - 确认机制不可被绕过
  - 确认超时自动拒绝
  - 批量确认风险控制

- **信任级别分层**
  - 操作风险等级划分
  - 信任阈值动态调整
  - 用户信任级别管理
  - 上下文感知信任评估

- **透明度要求**
  - Agent 行为可解释
  - 决策过程可追溯
  - 用户知情同意
  - 能力边界清晰告知

- **撤销与回滚**
  - 操作可撤销
  - 状态回滚能力
  - 撤销时效限制
  - 撤销审计记录

**交叉引用**: 与 ext-13 AI-05 (Agent Action Control) LLM08 (Excessive Agency) 互补

**OWASP ASI 映射**: ASI05 - Unexpected Code Execution, ASI09 - Human-Agent Trust Exploitation

---

### AGENT-09: Prompt & Skill Template Security (提示词与技能模板安全)
**控制要求**: Prompt 模板和 Skill 定义必须安全管理，防止恶意篡改和注入

**适用范围**: Prompt Templates, Skills, Custom Instructions

**控制措施**:
- **模板完整性**
  - 模板版本控制
  - 模板签名验证
  - 变更审批流程
  - 模板来源验证

- **注入防护**
  - 变量边界清晰定义
  - 用户输入与模板隔离
  - 特殊字符转义
  - 嵌套注入检测

- **Skill 安全评估**
  - Skill 能力声明审核
  - Skill 行为测试
  - Skill 依赖审查
  - Skill 沙箱执行

- **模板访问控制**
  - 模板读/写权限分离
  - 敏感模板加密存储
  - 模板使用审计
  - 模板泄露检测

**交叉引用**: 与 ext-13 AI-01 (Prompt Injection Prevention), ext-12 SUPPLY-04 (Source Verification) 互补

**OWASP ASI 映射**: ASI01 - Agent Goal Hijack (via Prompt), ASI04 - Agentic Supply Chain (Skills)

---

### AGENT-10: Agentic Supply Chain Security (Agent 供应链安全)
**控制要求**: Agent 相关组件的供应链必须安全可控

**适用范围**: Agent Frameworks, MCP Servers, Tools, Skills, Plugins

**控制措施**:
- **框架安全**
  - Agent 框架漏洞监控
  - 框架版本管理
  - 安全补丁及时应用
  - 框架配置审计

- **MCP Server 供应链**
  - MCP Server 来源验证
  - Server 代码审查
  - 依赖项扫描
  - 恶意 Server 检测

- **Tool/Skill 供应链**
  - Tool 来源白名单
  - Skill 发布者验证
  - 代码签名验证
  - 恶意代码扫描

- **第三方集成安全**
  - 第三方服务安全评估
  - API 凭证安全管理
  - 集成点监控
  - 数据流安全

**交叉引用**: 与 ext-12 (Supply Chain Security) 全面互补

**OWASP ASI 映射**: ASI04 - Agentic Supply Chain Vulnerabilities

---

## Control Applicability Matrix

| 控制 | Agent 系统 | MCP Tools | Skills | Prompts | Multi-Agent |
|------|:----------:|:---------:|:------:|:-------:|:-----------:|
| AGENT-01 | ● | ○ | ● | ● | ● |
| AGENT-02 | ● | ● | ● | ○ | ● |
| AGENT-03 | ● | ● | ○ | ○ | ● |
| AGENT-04 | ● | ○ | ○ | ○ | ● |
| AGENT-05 | ● | ○ | ○ | ○ | ● |
| AGENT-06 | ● | ○ | ● | ○ | ● |
| AGENT-07 | ● | ○ | ○ | ○ | ● |
| AGENT-08 | ● | ● | ● | ○ | ● |
| AGENT-09 | ○ | ○ | ● | ● | ○ |
| AGENT-10 | ● | ● | ● | ○ | ● |

**Legend**: ● 强相关 | ○ 弱相关或按需

---

## L4 References

详细实践指南参考 `references/` 目录：
- reference-set-17-agentic-security.md
- reference-set-17-mcp-security.md
- reference-set-17-multi-agent-patterns.md
- reference-set-17-skill-security.md

内部参考：
- agentic-threats.yaml
- llm-threats.yaml (交叉引用)

外部参考：
- OWASP Top 10 for Agentic Applications 2026
- OWASP Non-Human Identities (NHI) Top 10
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

---

## STRIDE Mapping

| STRIDE | Applicable Controls | Threat Examples |
|--------|---------------------|-----------------|
| S | AGENT-03, AGENT-05 | Agent 身份伪造, A2A 消息伪造 |
| T | AGENT-01, AGENT-04, AGENT-09 | 目标篡改, 记忆污染, 模板注入 |
| R | AGENT-06, AGENT-08 | 行为不可追溯, 操作无法审计 |
| I | AGENT-04, AGENT-05 | 记忆泄露, Agent 间数据泄露 |
| D | AGENT-07 | 级联故障导致服务不可用 |
| E | AGENT-01, AGENT-02, AGENT-06 | 目标劫持提权, 工具滥用, Rogue Agent |

---

## Relationship with ext-13 (AI/LLM Security)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        安全控制层次关系                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Application Layer                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  ext-16: Agentic Security (AGENT)                                │   │
│  │  ───────────────────────────────────────────────────────────    │   │
│  │  • Agent 行为与意图安全                                          │   │
│  │  • 工具/技能治理                                                 │   │
│  │  • 多 Agent 协作安全                                             │   │
│  │  • 人机信任边界                                                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │ 依赖                                     │
│                              ▼                                          │
│  Model Layer                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  ext-13: AI/LLM Security (AI)                                    │   │
│  │  ───────────────────────────────────────────────────────────    │   │
│  │  • 提示词注入防护                                                │   │
│  │  • 输出验证                                                      │   │
│  │  • 模型访问控制                                                  │   │
│  │  • 数据隔离                                                      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  Relationship: ext-16 EXTENDS ext-13 (Agent builds on LLM)              │
│  Cross-references: AGENT-01↔AI-01, AGENT-02↔AI-05, AGENT-04↔AI-04      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-03 | Initial release based on OWASP Agentic Top 10 2026 |
