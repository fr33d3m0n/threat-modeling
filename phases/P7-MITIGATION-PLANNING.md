# Phase 7: Mitigation Planning

**Type**: Prescriptive
**Executor**: LLM
**Knowledge**: Control Sets, CWE Mitigations, ASVS

---

## Input Context

← P6: `validated_risks` (complete Phase 6 output)

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
```

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
