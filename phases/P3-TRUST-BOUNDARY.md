<!-- Threat Modeling Skill | Version 3.0.0 (20260202a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Phase 3: Trust Boundary Evaluation

**Type**: Evaluative
**Executor**: LLM
**Knowledge**: Security Principles (ZT, SOD, LP), security-design.yaml

---

## ⚠️ MANDATORY: 4-Phase Gating Protocol (BLOCKING)

> **CRITICAL**: 必须按顺序完成以下四个阶段，并**输出每个阶段的结果**。跳过任何阶段将导致分析质量下降！

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🧠 THINKING - Phase 3 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Purpose**: 基于P2 DFD识别信任边界，评估跨边界安全态势。

**⚠️ 你必须输出以下格式的 THINKING 结果：**

```
🧠 THINKING - P3 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 CORE PROBLEM
识别所有信任边界，评估跨边界流的安全控制

📊 UPSTREAM DATA (从 P2 YAML 读取)
| 指标 | 值 | 来源 |
|------|-----|------|
| P2外部交互者数 | {实际值} | P2_dfd_elements.yaml → dfd_elements.external_interactors 长度 |
| P2进程数 | {实际值} | P2_dfd_elements.yaml → dfd_elements.processes 长度 |
| P2数据存储数 | {实际值} | P2_dfd_elements.yaml → dfd_elements.data_stores 长度 |
| P2数据流数 | {实际值} | P2_dfd_elements.yaml → dfd_elements.data_flows 长度 |
| L1覆盖得分 | {实际值} | P2_dfd_elements.yaml → l1_coverage.overall.overall_score |

❓ UNKNOWNS
- 信任边界类型分布 (Network/Process/User/Data/Service/Model/Agent)
- 跨边界流的安全控制
- 敏感数据节点位置

⚠️ RISKS
- DFD元素未全部映射到边界区域
- 跨边界流缺少安全控制记录
- 边界图遗漏关键crossing points

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⛔ STOP CHECK
- P2 YAML 已读取? [YES/NO]
- 上游数据完整 (DFD元素数均有值)? [YES/NO]
- 可以继续PLANNING? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ **STOP条件**: 如果任何 STOP CHECK = NO → 先读取P2数据再继续

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 📋 PLANNING - Sub-task Decomposition
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Step 1: 读取上游数据** (BLOCKING - 必须执行)
```bash
# 读取P2 YAML数据
python scripts/phase_data.py --query --phase 2 --summary --root .
python scripts/phase_data.py --query --phase 2 --type dfd --root .

# 或直接读取
cat .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
```
⛔ 如果P2 YAML不存在或无效 → STOP并返回完成P2

**Step 2: 输出子任务表格** (MANDATORY)

**⚠️ 你必须输出以下格式的 PLANNING 结果：**

```
📋 PLANNING - P3 Sub-tasks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| # | 子任务 | 预期输出 |
|---|--------|----------|
| T1 | 读取P2 DFD数据，提取元素清单 | 数据结构 |
| T2 | 识别信任边界 (TB-xxx)，确定类型 | 边界清单 |
| T3 | 分析跨边界数据流 | 跨边界流映射 |
| T4 | 评估接口安全 (认证/授权/加密) | 安全控制评估 |
| T5 | 映射敏感数据节点 | 敏感数据标记 |
| T6 | 生成边界图 (ASCII + Mermaid) | 可视化图表 |
| T7 | 写入最终输出 | P3_boundary_context.yaml + MD |

⛔ PLANNING CHECK
- 子任务已分解? [YES/NO]
- 准备创建 TaskCreate? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Step 3: TaskCreate for ALL sub-tasks** (MANDATORY)

⚠️ 在开始任何实施前，必须执行 `TaskCreate` 创建所有子任务！

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### ⚡ EXECUTION LOOP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For each sub-task:
1. `TaskUpdate(status: "in_progress")`
2. 实施子任务
3. 验证: 输出是否符合预期？
4. If 验证通过: `TaskUpdate(status: "completed")` → 下一个
5. If 验证失败: 诊断 → 修复 → 重试 (max 3x) → 如仍失败: CHECKPOINT请求用户决策

**输出顺序** (CRITICAL):
1. **先写YAML**: `.phase_working/{SESSION_ID}/data/P3_boundary_context.yaml`
2. **后写MD**: `.phase_working/{SESSION_ID}/reports/P3-TRUST-BOUNDARY.md`

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🔍 REFLECTION - Completion Verification
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**⚠️ 完成 EXECUTION 后，你必须输出以下格式的 REFLECTION 结果：**

```
🔍 REFLECTION - P3 Completion Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 检查项 | 状态 |
|--------|------|
| P2 YAML数据已读取并理解? | [✅/❌] |
| P3_boundary_context.yaml 存在且有效? | [✅/❌] |
| 所有TB-xxx边界已识别并分类? | [✅/❌] |
| 所有DFD元素已映射到边界区域? | [✅/❌] |
| 所有跨边界流有安全控制记录? | [✅/❌] |
| 边界图 (ASCII) 已包含? | [✅/❌] |
| boundary_findings 存在 (即使为空)? | [✅/❌] |
| Hook验证通过 (exit 0)? | [✅/❌] |

⛔ COMPLETION GATE
- 所有检查通过? [YES/NO]
- 可以进入P4? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ 任何检查失败 → 修复并重新验证，直到全部通过

---

## ⚠️ MANDATORY OUTPUT RULES

> **CRITICAL**: Phase 3 requires TWO outputs - a YAML data file AND a Markdown report.

### Dual Output Requirement

```
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 3 MUST PRODUCE TWO FILES:                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. DATA FILE (PRIMARY - Write First!)                              │
│     Path: .phase_working/{SESSION_ID}/data/P3_boundary_context.yaml │
│     Purpose: Structured data for P4 to read                         │
│     Format: Valid YAML with schema_version: "3.0.0 (20260201a)"                   │
│                                                                      │
│  2. REPORT FILE (SECONDARY - Write After Data!)                     │
│     Path: .phase_working/{SESSION_ID}/reports/P3-TRUST-BOUNDARY.md  │
│     Purpose: Human-readable trust boundary analysis                 │
│     Format: Markdown with diagrams and matrices                     │
│                                                                      │
│  INPUT REQUIREMENT:                                                  │
│     Read: .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml     │
│     ❌ DO NOT read P2's .md report for data extraction              │
│     ✅ REQUIRED: Parse P2's YAML for dfd_elements                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Required Data Sections in YAML

| Section | Validation |
|---------|------------|
| `boundary_context.boundaries[]` | BLOCKING - all trust boundaries with TB-xxx IDs |
| `boundary_context.interfaces[]` | BLOCKING - cross-boundary interfaces |
| `boundary_context.data_nodes[]` | BLOCKING - sensitive data locations |
| `boundary_context.cross_boundary_flows[]` | BLOCKING - all boundary crossings |
| `boundary_findings` | WARNING - security observations from boundary analysis |

### Validation Gate

Phase 3 CANNOT complete until:
1. `.phase_working/{SESSION_ID}/data/P3_boundary_context.yaml` exists and is valid YAML
2. Every DFD element mapped to a trust boundary zone
3. All cross-boundary flows have security controls documented
4. `.phase_working/{SESSION_ID}/reports/P3-TRUST-BOUNDARY.md` exists

---

## Input Context

← P2: `dfd_elements` from `.phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml`

### ⚠️ MANDATORY: Query P2 Data Before Analysis

**Before starting P3 analysis**, LLM MUST execute these queries to obtain P2 data:

```bash
# Step 1: Get P2 summary for DFD overview
python scripts/phase_data.py --query --phase 2 --summary --root .

# Step 2: Get detailed DFD elements (REQUIRED for boundary mapping)
python scripts/phase_data.py --query --phase 2 --type dfd --root .

# Step 3: Get data flows (REQUIRED for cross-boundary analysis)
python scripts/phase_data.py --query --phase 2 --type flows --root .
```

**Or read YAML directly**:
```bash
# PRIMARY source - REQUIRED
cat .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
```

**CRITICAL**: Do NOT generate P3 trust boundaries from memory. MUST read P2 DFD data first!

## Output Context

→ P4: `boundary_context` {boundaries[], interfaces[], data_nodes[], cross_boundary_flows[]}

---

## Core Analysis Goal

Based on DFD, identify trust boundaries, key interfaces, and data nodes; evaluate security posture at boundary crossings.

---

## Knowledge Reference

**Security Principles**:
- Zero Trust (ZT): Never trust, always verify
- Separation of Duties (SOD): Critical ops require multiple parties
- Least Privilege (LP): Minimum permissions required
- Least Agency (LA): Limit AI agent autonomy

**Security Domains**: AUTHN, AUTHZ, API from `security-design.yaml`

---

## Error Handling

| Error | Cause | Recovery Action |
|-------|-------|-----------------|
| P2 YAML not found | P2 not completed | Return to P2, complete DFD analysis |
| DFD elements incomplete | Missing flows or stores | Return to P2 for supplemental analysis |
| Boundary mapping failure | Complex architecture | Break into smaller zones, consult architect |
| Cross-boundary flow gaps | Incomplete P2 data | Document gaps, flag for manual review |

**Fallback Strategy**: If boundary analysis cannot complete due to data gaps, document known boundaries and mark incomplete zones with `status: partial` and `gaps: ["description"]`.

---

## Trust Boundary Types

| Type | Description | Example |
|------|-------------|---------|
| Network | Network segment boundaries | Internet/DMZ, DMZ/Internal |
| Process | Process isolation boundaries | Container, VM, Sandbox |
| User | User privilege boundaries | Anonymous/Authenticated, User/Admin |
| Data | Data sensitivity boundaries | Public/Internal/Confidential |
| Service | Service trust boundaries | Internal/External services |
| **Model** | AI/LLM model boundaries | User/Model, Model/Tool, Model/Data |
| **Agent** | AI agent autonomy boundaries | Human/Agent, Agent/External API |

---

## Analysis Tasks

### 1. Identify Trust Boundaries

For each boundary:
- Assign ID: TB-xxx
- Determine type (Network/Process/User/Data/Service)
- Define scope (which elements are inside)
- Identify crossing points

### 2. Analyze Cross-Boundary Flows

For each data flow crossing a boundary:
- Source boundary zone
- Destination boundary zone
- Security controls at crossing
- Risk assessment

### 3. Evaluate Interface Security

For each cross-boundary interface:
- Authentication mechanism
- Authorization checks
- Data validation
- Encryption status

### 4. Map Sensitive Data Nodes

Identify where sensitive data resides relative to boundaries:
- Which boundary zone
- Access controls
- Encryption status

---

## Output Structure

```yaml
boundary_context:
  boundaries:
    - id: TB-001
      name: "Internet Boundary"
      type: Network
      description: "Boundary between internet and DMZ"
      inside: [P-001]           # Elements inside
      outside: [EI-001, EI-002] # Elements outside
      crossing_points:
        - flow_id: DF-001
          direction: inbound
          controls: [TLS, WAF, Rate-Limit]

  interfaces:
    - id: IF-001
      boundary: TB-001
      entry_side: "Internet"
      exit_side: "DMZ"
      protocol: HTTPS
      authentication: "None (public endpoint)"
      authorization: "N/A"
      validation: "Input sanitization"
      encryption: "TLS 1.3"
      risk_level: HIGH

  data_nodes:
    - id: DN-001
      data_store: DS-001
      data_types: ["User PII", "Credentials"]
      sensitivity: CRITICAL
      boundary_zone: "Internal Network"
      access_controls: ["Role-based", "MFA required"]
      encryption:
        at_rest: true
        in_transit: true

  cross_boundary_flows:
    - flow_id: DF-001
      source_zone: "Internet"
      dest_zone: "DMZ"
      boundaries_crossed: [TB-001]
      data_sensitivity: MEDIUM
      security_controls:
        authentication: "Session token"
        encryption: "TLS 1.3"
        validation: "Input sanitization"
      risk_assessment:
        level: MEDIUM
        concerns: ["Public exposure", "Credential handling"]
```

---

## Boundary Diagram Template

```
┌─────────────────────────────────────────────────────────────────┐
│                     Trust Boundary Diagram                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ╔══════════════════════════════════════════════════════════╗   │
│  ║ TB-001: Internet Boundary                                 ║   │
│  ╠══════════════════════════════════════════════════════════╣   │
│  ║                                                           ║   │
│  ║  ┌─────────┐                                             ║   │
│  ║  │ EI-001  │                                             ║   │
│  ║  │Web User │──────────┐                                  ║   │
│  ║  └─────────┘          │ DF-001                           ║   │
│  ║                       │ [TLS, WAF]                       ║   │
│  ╚═══════════════════════╪══════════════════════════════════╝   │
│                          │                                       │
│  ╔═══════════════════════╪══════════════════════════════════╗   │
│  ║ TB-002: DMZ          ▼                                    ║   │
│  ╠══════════════════════════════════════════════════════════╣   │
│  ║  ┌─────────┐        ┌─────────┐                          ║   │
│  ║  │  P-001  │───────▶│  P-002  │                          ║   │
│  ║  │API Gate │ DF-002 │Auth Svc │                          ║   │
│  ║  └─────────┘        └────┬────┘                          ║   │
│  ╚═══════════════════════════╪══════════════════════════════╝   │
│                              │                                   │
│  ╔═══════════════════════════╪══════════════════════════════╗   │
│  ║ TB-003: Internal Network  │ DF-003                        ║   │
│  ╠═══════════════════════════╪══════════════════════════════╣   │
│  ║                           ▼                               ║   │
│  ║                     ┌─────────┐                           ║   │
│  ║                     │ DS-001  │                           ║   │
│  ║                     │User DB  │                           ║   │
│  ║                     └─────────┘                           ║   │
│  ╚══════════════════════════════════════════════════════════╝   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Assessment Matrix

| Boundary | Crossing Flows | Auth | Encryption | Validation | Risk |
|----------|----------------|------|------------|------------|------|
| TB-001 | DF-001, DF-010 | Token | TLS 1.3 | Input sanitization | Medium |
| TB-002 | DF-002, DF-003 | mTLS | TLS 1.3 | Schema validation | Low |
| TB-003 | DF-003 | DB Auth | TLS 1.3 | Parameterized queries | Low |

---

## Boundary Issues to Identify

1. **Missing Controls**: Boundaries without adequate authentication
2. **Weak Encryption**: Unencrypted or weak encryption at crossings
3. **Excessive Permissions**: Cross-boundary access with excessive privileges
4. **Missing Validation**: Input not validated at boundary crossings
5. **Sensitive Data Exposure**: Sensitive data crossing to lower-trust zones

---

## Report Template

```markdown
# P3: Trust Boundary Evaluation

## Boundary Summary

| Boundary | Type | Elements Inside | Crossing Flows |
|----------|------|-----------------|----------------|
| TB-001 | Network | P-001 | DF-001 |
| TB-002 | Network | P-001, P-002 | DF-002, DF-003 |

## Trust Boundary Diagram

[ASCII diagram]

## Cross-Boundary Flow Analysis

### DF-001: User Request (Internet → DMZ)
- **Source Zone**: Internet
- **Dest Zone**: DMZ
- **Security Controls**: TLS 1.3, WAF, Rate Limiting
- **Risk Level**: Medium
- **Concerns**: Public exposure

## Interface Security Assessment

[Assessment matrix]

## Sensitive Data Mapping

| Data Node | Location | Sensitivity | Protection |
|-----------|----------|-------------|------------|
| DN-001 | Internal | CRITICAL | Encrypted, RBAC |

## Boundary Findings

[yaml:boundary_findings block - see below]

```yaml:boundary_findings
findings:
  - id: F-P3-001
    type: boundary
    title: "Finding title"
    description: "Detailed description"
    severity: HIGH      # CRITICAL|HIGH|MEDIUM|LOW|INFO
    category: missing_control|weak_encryption|excessive_permission|unprotected_crossing
    location:
      boundary_id: TB-xxx
      interface_id: IF-xxx
      flow_id: DF-xxx
    affected_elements:
      - type: trust_boundary
        id: TB-xxx
      - type: cross_boundary_flow
        id: DF-xxx
    security_relevance: "Why this matters for security"
    crossing_risk: HIGH  # Risk level of boundary crossing
    recommended_action: "What to investigate in later phases"

summary:
  total: 0
  by_severity:
    critical: 0
    high: 0
    medium: 0
    low: 0
    info: 0
  by_category:
    missing_control: 0
    weak_encryption: 0
    excessive_permission: 0
    unprotected_crossing: 0
```

**Finding Categories**:
- `missing_control`: Boundary crossing without security control
- `weak_encryption`: Inadequate encryption at boundary
- `excessive_permission`: Cross-boundary access with excessive privileges
- `unprotected_crossing`: Input not validated at boundary

## Recommendations

1. ...
2. ...
```

---

## Completion Checklist

Before marking Phase 3 complete:

- [ ] All trust boundaries identified (TB-xxx)
- [ ] All cross-boundary flows analyzed
- [ ] Interface security assessed
- [ ] Sensitive data nodes mapped
- [ ] Trust boundary diagram included
- [ ] yaml:boundary_findings present (even if empty)
- [ ] Boundary issues documented
- [ ] Validation passed

---

**End of Phase 3 Instructions** (~200 lines, ~1.5K tokens)
