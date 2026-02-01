<!-- Threat Modeling Skill | Version 3.0.0 (20260201b) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Phase 7: Mitigation Planning

**Type**: Prescriptive
**Executor**: LLM
**Knowledge**: Control Sets, CWE Mitigations, ASVS

---

## ⚠️ MANDATORY: 4-Phase Gating Protocol (BLOCKING)

> **CRITICAL**: 必须按顺序完成以下四个阶段。跳过任何阶段将导致分析质量下降！
> **⚠️ CHECKPOINT PHASE**: P7是用户检查点，缓解措施完成后请求用户确认。

### ① THINKING (理解阶段) - 在任何规划前完成

**Purpose**: 基于P6验证的风险设计具体、可实施的缓解措施。

在开始P7分析前，必须明确回答以下问题：

```yaml
thinking_checkpoint:
  core_problem: "为每个VR-xxx设计具体的缓解措施MIT-xxx，包含可执行的代码示例"
  what_i_know:
    - "P6已验证风险数: [从P6 YAML读取 risk_summary.total_verified]"
    - "P6理论风险数: [从P6 YAML读取 risk_summary.total_theoretical]"
    - "P6 Critical风险数: [从P6 YAML读取 risk_summary.risk_by_severity.critical]"
    - "P6 High风险数: [从P6 YAML读取 risk_summary.risk_by_severity.high]"
    - "Tech stack: [从P1 YAML project_context.tech_stack]"
  what_i_dont_know:
    - "[具体代码修复位置]"
    - "[最佳实践实施细节]"
    - "[ASVS合规要求]"
  what_could_go_wrong:
    - "VR-xxx缺少对应的MIT-xxx"
    - "缓解措施过于泛化 (无具体代码)"
    - "缺少验证步骤"
    - "KB缓解覆盖率过低"
```

⛔ **STOP条件**: 如果P6风险数未从YAML读取 → 先读取P6数据再继续

### ② PLANNING (规划阶段) - 理解确认后

**Purpose**: 分解为可验证的子任务，确保每个风险有缓解措施。

**Step 1: 读取上游数据** (BLOCKING - 必须执行)
```bash
# 读取P6验证风险
python scripts/phase_data.py --query --phase 6 --summary --root {PROJECT_ROOT}
python scripts/phase_data.py --query --phase 6 --type risks --root {PROJECT_ROOT}

# 或直接读取
cat .phase_working/{SESSION_ID}/data/P6_validated_risks.yaml
```
⛔ 如果P6 YAML不存在或无效 → STOP并返回完成P6

**Step 2: 分解子任务** (建议3-7个)
```
- T1: 读取P6数据，提取VR-xxx清单
- T2: 为P0 (Critical)风险设计立即缓解措施
- T3: 为P1 (High)风险设计紧急缓解措施
- T4: 为P2/P3风险设计计划缓解措施
- T5: KB查询 - CWE缓解和ASVS映射
- T6: 创建实施路线图
- T7: 写入P7_mitigation_plan.yaml + P7-MITIGATION-PLAN.md
```

**Step 3: TaskCreate for ALL sub-tasks** (MANDATORY)
```
⚠️ 在开始任何实施前，TaskList必须显示所有子任务！
```

### ③ EXECUTION LOOP (执行阶段)

For each sub-task:
1. `TaskUpdate(status: "in_progress")`
2. 实施子任务
3. 验证: 输出是否符合预期？
4. If 验证通过: `TaskUpdate(status: "completed")` → 下一个
5. If 验证失败: 诊断 → 修复 → 重试 (max 3x) → 如仍失败: CHECKPOINT请求用户决策

**输出顺序** (CRITICAL):
1. **先写YAML**: `.phase_working/{SESSION_ID}/data/P7_mitigation_plan.yaml`
2. **后写MD**: `.phase_working/{SESSION_ID}/reports/P7-MITIGATION-PLAN.md`

**关键KB查询**:
```bash
$SKILL_PATH/kb --cwe CWE-89 --mitigations      # CWE特定缓解
$SKILL_PATH/kb --control authentication         # 安全控制详情
$SKILL_PATH/kb --asvs-level L2                  # ASVS要求
```

**缓解覆盖验证**:
```
∀ VR-xxx ∈ P6.validated_risks → ∃ MIT-xxx ∈ P7.mitigation_plan
```

### ④ REFLECTION (反思阶段) - 完成前必须确认

Before marking Phase 7 complete, verify ALL:

- [ ] P6 YAML数据已读取并理解？
- [ ] P7_mitigation_plan.yaml 存在且有效？
- [ ] 每个VR-xxx有对应的MIT-xxx？
- [ ] kb_mitigation_sources 存在？
- [ ] P0/P1风险的MIT-xxx有KB引用？
- [ ] implementation_steps 包含具体代码？
- [ ] roadmap (immediate/short/medium/long) 已定义？
- [ ] ASVS/WSTG引用已提供？
- [ ] Hook验证通过 (exit 0)？

⛔ 任何检查失败 → 修复并重新验证，直到全部通过

---

## ⚠️ MANDATORY OUTPUT RULES

> **CRITICAL**: Phase 7 requires TWO outputs - a YAML data file AND a Markdown report.

### Dual Output Requirement

```
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 7 MUST PRODUCE TWO FILES:                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. DATA FILE (PRIMARY - Write First!)                              │
│     Path: .phase_working/{SESSION_ID}/data/P7_mitigation_plan.yaml  │
│     Purpose: Structured mitigation data for P8 to read              │
│     Format: Valid YAML with schema_version: "3.0.0 (20260201a)"                   │
│                                                                      │
│  2. REPORT FILE (SECONDARY - Write After Data!)                     │
│     Path: .phase_working/{SESSION_ID}/reports/P7-MITIGATION-PLAN.md │
│     Purpose: Human-readable mitigation roadmap                      │
│     Format: Markdown with code examples and timelines               │
│                                                                      │
│  INPUT REQUIREMENT:                                                  │
│     Read: .phase_working/{SESSION_ID}/data/P6_validated_risks.yaml  │
│     ❌ DO NOT read previous .md reports for data extraction         │
│     ✅ REQUIRED: Parse YAML files for validated_risks               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Required Data Sections in YAML

| Section | Validation |
|---------|------------|
| `mitigation_plan.mitigations[]` | BLOCKING - all mitigations with MIT-xxx IDs |
| `mitigation_plan.roadmap` | BLOCKING - timeline with priorities |

### Validation Gate

Phase 7 CANNOT complete until:
1. `.phase_working/{SESSION_ID}/data/P7_mitigation_plan.yaml` exists and is valid YAML
2. Every validated risk (VR-xxx) has corresponding mitigation (MIT-xxx)
3. Implementation steps are specific (not generic)
4. `.phase_working/{SESSION_ID}/reports/P7-MITIGATION-PLAN.md` exists

---

## Error Handling

| Error | Cause | Recovery Action |
|-------|-------|-----------------|
| P6 YAML not found | P6 not completed | Return to P6, complete risk validation |
| Missing risk_refs | Orphan mitigation | Link MIT-xxx to VR-xxx, verify coverage |
| Generic mitigation | Insufficient detail | Add specific code/config with file:line references |
| KB lookup failure | Knowledge base error | Provide manual ASVS/WSTG reference |

**Fallback Strategy**: If specific implementation cannot be determined due to missing code context, mark mitigation with `implementation_level: guidance` and provide general security principles.

---

## Input Context

← P6: `validated_risks` from `.phase_working/{SESSION_ID}/data/P6_validated_risks.yaml`

### ⚠️ MANDATORY: Query P6 Data Before Planning

**Before starting P7 mitigation planning**, LLM MUST execute these queries to obtain P6 validated risks:

```bash
# Step 1: Get P6 risk summary for overview
python scripts/phase_data.py --query --phase 6 --summary --root {PROJECT_ROOT}

# Step 2: Get detailed validated risks (PRIMARY input)
python scripts/phase_data.py --query --phase 6 --type risks --root {PROJECT_ROOT}

# Step 3: Verify P6 coverage for completeness
python scripts/phase_data.py --verify-p6-coverage --root {PROJECT_ROOT}
```

**Or read YAML directly**:
```bash
# PRIMARY source - REQUIRED
cat .phase_working/{SESSION_ID}/data/P6_validated_risks.yaml
```

**CRITICAL**: Every VR-xxx in P6 MUST have a corresponding MIT-xxx mitigation!
```
∀ VR-xxx ∈ P6.validated_risks → ∃ MIT-xxx ∈ P7.mitigation_plan
```

Do NOT plan mitigations from memory. MUST read P6 validated risks first!

## Output Context

→ P8: `mitigation_plan` {mitigations[], roadmap{}}

---

## Core Analysis Goal

Design specific mitigation measures and implementation plans for each validated risk. Focus on actionable, tech-stack-specific remediation that developers can implement.

---

## Knowledge Reference

**Query Commands**:
```bash
$SKILL_PATH/kb --cwe CWE-89 --mitigations      # CWE-specific mitigations
$SKILL_PATH/kb --control authentication         # Security control details
$SKILL_PATH/kb --asvs-level L2                  # ASVS requirements
$SKILL_PATH/kb --asvs-chapter V4                # ASVS by chapter
$SKILL_PATH/kb --wstg V1                        # OWASP WSTG tests
```

### KB Mitigation Sources (MANDATORY per GAP-4 Contract)

> **CRITICAL**: P7 MUST query KB for mitigation guidance per KBQueryContract in assets/contracts/data-model.yaml

**Required Queries per Risk**:
1. `--cwe CWE-{NNN} --mitigations` - For each risk's related_cwe
2. `--asvs-level {L1|L2|L3}` - For verification requirements
3. `--control {domain}` - For implementation guidance

```yaml
# In P7_mitigation_plan.yaml - MANDATORY section (GAP-4 Contract)
kb_mitigation_sources:
  # Query record
  queries_made:
    - query: "--cwe CWE-287 --mitigations"
      timestamp: "2026-01-31T14:30:00Z"
      result_count: 8
      usage: "Informed MIT-001 implementation steps"
      mitigations_informed: [MIT-001, MIT-002]
    - query: "--asvs-level L2"
      timestamp: "2026-01-31T14:30:15Z"
      result_count: 286
      usage: "Populated verification.asvs_requirement fields"
      mitigations_informed: [MIT-001, MIT-002, MIT-003]
    - query: "--control authentication"
      timestamp: "2026-01-31T14:30:30Z"
      result_count: 15
      usage: "Detailed implementation guidance for auth controls"
      mitigations_informed: [MIT-001]

  # Source tracking per mitigation
  mitigation_kb_refs:
    - mitigation_id: MIT-001
      cwe_ref: CWE-287
      cwe_mitigations_applied: ["Use multi-factor authentication", "Implement secure session management"]
      asvs_requirement: "V2.1.1"
      control_guidance: "control-set-01"
    - mitigation_id: MIT-002
      cwe_ref: CWE-89
      cwe_mitigations_applied: ["Use parameterized queries", "Apply input validation"]
      asvs_requirement: "V5.3.4"
      control_guidance: "control-set-03"

  # Coverage metrics (MANDATORY)
  coverage:
    total_mitigations: 25
    cwes_with_mitigations: 22       # Mitigations with CWE --mitigations query
    asvs_requirements_mapped: 20    # Mitigations with ASVS refs
    control_guidance_applied: 18    # Mitigations with control refs
    p0_p1_mitigations_total: 8
    p0_p1_with_kb_ref: 8            # MUST be 100% - ERROR if not
    mitigation_kb_coverage: 88.0    # cwes_with_mitigations / total_mitigations

  # Error handling
  errors:
    - query: "--cwe CWE-9999 --mitigations"
      error_type: "not_found"
      action_taken: "Used general CWE category mitigations"
      affected_mitigations: [MIT-015]

  kb_available: true
```

**Validation Rules** (GAP-4 Contract):
- **ERROR**: P0/P1 mitigation without any KB reference (`p0_p1_with_kb_ref < p0_p1_mitigations_total`)
- **WARNING**: `mitigation_kb_coverage < 70%`
- **INFO**: Generic mitigations should reference control guidance even if CWE-specific unavailable

---

## Mitigation Priority Framework

| Risk Priority | Timeline | Action |
|---------------|----------|--------|
| P0 (Critical) | Immediate | Emergency fix, hotfix deployment |
| P1 (High) | 24-48 hours | Urgent patch, next release |
| P2 (Medium) | 7 days | Planned fix, sprint priority |
| P3 (Low) | 30 days | Backlog, technical debt |

---

## Mitigation Structure

```yaml
mitigation_plan:
  mitigations:
    - id: MIT-001
      title: "Enable JWT Signature Verification"
      risk_refs: [VR-001]                  # MANDATORY: Link to risks
      threat_refs: [T-S-P-001-001, T-E-P-001-002]
      priority: P0
      effort: LOW                          # LOW/MEDIUM/HIGH
      implementation_time: "2 hours"

      # Current State
      current_implementation: |
        jwt.decode(token, options={"verify_signature": False})

      # Recommended Fix
      recommended_fix: |
        # Use proper secret key from environment
        secret_key = os.environ.get('JWT_SECRET_KEY')
        jwt.decode(token, secret_key, algorithms=['HS256'])

      # Detailed Implementation
      implementation_steps:
        - step: 1
          action: "Generate secure JWT secret"
          code: |
            # Generate 256-bit random key
            openssl rand -base64 32 > jwt_secret.txt

        - step: 2
          action: "Store secret in environment"
          code: |
            # .env file
            JWT_SECRET_KEY=<generated-key>

        - step: 3
          action: "Update token verification"
          file: "src/api/auth.py"
          line: 45
          before: |
            def verify_token(token):
                return jwt.decode(token, options={"verify_signature": False})
          after: |
            def verify_token(token):
                secret_key = os.environ.get('JWT_SECRET_KEY')
                if not secret_key:
                    raise ValueError("JWT_SECRET_KEY not configured")
                return jwt.decode(token, secret_key, algorithms=['HS256'])

        - step: 4
          action: "Add unit test"
          code: |
            def test_token_verification_rejects_invalid_signature():
                invalid_token = jwt.encode(
                    {"user_id": "admin"},
                    "wrong_key",
                    algorithm="HS256"
                )
                with pytest.raises(jwt.InvalidSignatureError):
                    verify_token(invalid_token)

      # Verification
      verification:
        test_cases:
          - "Verify valid token is accepted"
          - "Verify invalid signature is rejected"
          - "Verify tampered payload is rejected"
        asvs_requirement: "V3.5.3"
        wstg_test: "WSTG-ATHN-04"

      # Security Controls Applied
      security_controls:
        - control: "Cryptographic verification"
          domain: CRYPTO
        - control: "Authentication token validation"
          domain: AUTHN

      # Additional Recommendations
      additional_recommendations:
        - "Consider using asymmetric keys (RS256) for better key management"
        - "Implement token refresh mechanism"
        - "Add token revocation support"
```

---

## Mitigation Categories

### Code Fixes

Direct code modifications to remediate vulnerabilities:

```yaml
code_fix:
  file: "src/api/auth.py"
  function: "verify_token"
  line_range: "45-50"
  fix_type: security_patch
  before: |
    # Vulnerable code
  after: |
    # Fixed code
  test: |
    # Verification test
```

### Configuration Changes

Security configuration updates:

```yaml
config_change:
  file: ".env.example"
  setting: "JWT_SECRET_KEY"
  current: "not set"
  recommended: "256-bit random key"
  impact: "All JWT operations"
```

### Infrastructure Changes

Infrastructure-level mitigations:

```yaml
infra_change:
  component: "API Gateway"
  change: "Enable WAF rate limiting"
  config: |
    # nginx rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
```

### Process Changes

Operational/process improvements:

```yaml
process_change:
  type: "Security policy"
  description: "Implement code review for auth changes"
  implementation: "Require security team review for auth/* files"
```

---

## Roadmap Structure

```yaml
roadmap:
  immediate:                    # P0 - Do now
    - MIT-001: "Enable JWT verification"
    - MIT-002: "Patch SQL injection"
    timeline: "Within 24 hours"
    owner: "Security Team"

  short_term:                   # P1 - This week
    - MIT-003: "Implement rate limiting"
    - MIT-004: "Add input validation"
    timeline: "7 days"
    owner: "Backend Team"

  medium_term:                  # P2 - This month
    - MIT-005: "Add MFA support"
    - MIT-006: "Implement audit logging"
    timeline: "30 days"
    owner: "Platform Team"

  long_term:                    # P3 - Backlog
    - MIT-007: "Security architecture review"
    - MIT-008: "Penetration testing program"
    timeline: "Q2 planning"
    owner: "Security Team"
```

---

## Report Template

```markdown
# P7: Mitigation Planning

## Executive Summary

| Priority | Count | Timeline |
|----------|-------|----------|
| P0 (Critical) | N | Immediate |
| P1 (High) | N | 24-48h |
| P2 (Medium) | N | 7 days |
| P3 (Low) | N | 30 days |

## Immediate Actions (P0)

### MIT-001: Enable JWT Signature Verification

**Risk**: VR-001 - JWT Bypass (CVSS 9.8)
**Effort**: LOW
**Timeline**: 2 hours

**Current Implementation**:
```python
jwt.decode(token, options={"verify_signature": False})
```

**Recommended Fix**:
```python
secret_key = os.environ.get('JWT_SECRET_KEY')
jwt.decode(token, secret_key, algorithms=['HS256'])
```

**Implementation Steps**:
1. Generate secure secret key
2. Store in environment variables
3. Update verify_token function
4. Add unit tests

**Verification**:
- [ ] Valid tokens accepted
- [ ] Invalid signatures rejected
- [ ] ASVS V3.5.3 compliance

## Short-Term Actions (P1)

### MIT-002: ...

## Implementation Roadmap

| Timeline | Mitigations | Owner |
|----------|-------------|-------|
| Immediate | MIT-001, MIT-002 | Security Team |
| 7 days | MIT-003, MIT-004 | Backend Team |
| 30 days | MIT-005, MIT-006 | Platform Team |

## Mitigation Plan

[yaml:mitigation_plan block]
```

---

## Quality Requirements

### Every Mitigation Must Include:

1. **risk_refs[]**: Link to VR-xxx from Phase 6
2. **Priority**: P0/P1/P2/P3
3. **Implementation Steps**: Actionable code/config changes
4. **Verification**: How to confirm fix works
5. **ASVS/WSTG References**: Compliance mapping

### Avoid Generic Recommendations

**Bad Example**:
```
"Implement proper input validation"
```

**Good Example**:
```python
# src/api/routes.py line 120
# Before:
query = f"SELECT * FROM users WHERE name = '{user_input}'"

# After:
query = "SELECT * FROM users WHERE name = %s"
cursor.execute(query, (user_input,))
```

---

## Validation Gates

| Check | Severity |
|-------|----------|
| yaml:mitigation_plan block present | BLOCKING |
| Every validated risk has mitigation | BLOCKING |
| Implementation steps are specific | WARNING |
| Verification tests defined | WARNING |
| ASVS/WSTG references provided | WARNING |

---

## Completion Checklist

Before marking Phase 7 complete:

- [ ] Every VR-xxx has corresponding MIT-xxx
- [ ] yaml:mitigation_plan present
- [ ] Roadmap with timeline defined
- [ ] Implementation steps are specific (not generic)
- [ ] Code examples provided for code fixes
- [ ] Verification steps defined
- [ ] Validation passed

---

**End of Phase 7 Instructions** (~250 lines, ~2K tokens)
