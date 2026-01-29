# Phase 4: Security Design Review

**Type**: Evaluative
**Executor**: LLM
**Knowledge**: Control Sets, OWASP References

---

## Input Context

← P1/P2/P3: All cumulative findings

## Output Context

→ P5: `security_gaps` {gaps[], design_matrix{}}

---

## Core Analysis Goal

Evaluate project's design maturity across all 16 security domains, identify gaps between current implementation and security best practices.

---

## Knowledge Reference (Progressive Loading)

1. **Always load**: `security-design.yaml` (16 domains overview)
2. **Per domain**: `control-set-*.md` when assessing that domain
3. **For details**: `reference-set-*.md` for specific implementation guidance

**Query Commands**:
```bash
$SKILL_PATH/kb --control authentication
$SKILL_PATH/kb --stride-controls S
$SKILL_PATH/kb --control api --full
```

---

## Security Domains (16)

| Seq | Code | Name | STRIDE Relevance |
|-----|------|------|------------------|
| 01 | AUTHN | Authentication & Session | S |
| 02 | AUTHZ | Authorization & Access Control | E |
| 03 | INPUT | Input Validation | T |
| 04 | OUTPUT | Output Encoding | T, I |
| 05 | CLIENT | Client-Side Security | S, T, I |
| 06 | CRYPTO | Cryptography & Transport | I |
| 07 | LOG | Logging & Monitoring | R |
| 08 | ERROR | Error Handling | I |
| 09 | API | API & Service Security | S, T, I, D, E |
| 10 | DATA | Data Protection | I |
| ext-11 | INFRA | Infrastructure Security | - |
| ext-12 | SUPPLY | Supply Chain Security | - |
| ext-13 | AI | AI/LLM Security | - |
| ext-14 | MOBILE | Mobile Security | - |
| ext-15 | CLOUD | Cloud Security | - |
| ext-16 | AGENT | Agentic Security | S, T, R, I, D, E |

---

## Assessment Process

For each domain:

1. **Identify Implementation**: What security controls exist in the code?
2. **Compare to Standards**: How does it compare to OWASP/industry standards?
3. **Assess Maturity**: Rate as Yes/No/Partial
4. **Document Gaps**: What's missing or inadequate?
5. **Assign Risk Level**: High/Medium/Low based on impact

---

## Assessment Matrix Template

| Domain | Code | Current Implementation | Assessment | Gap Description | Risk Level | KB Ref |
|--------|------|----------------------|------------|-----------------|------------|--------|
| Authentication | AUTHN | OAuth2 + local auth | Partial | MFA not implemented | High | control-set-01 |
| Authorization | AUTHZ | Role-based access | Yes | - | Low | control-set-02 |
| Input Validation | INPUT | Basic sanitization | Partial | Missing schema validation | Medium | control-set-03 |
| ... | ... | ... | ... | ... | ... | ... |

**Assessment Values**:
- **Yes**: Fully implemented per standards
- **Partial**: Partially implemented, gaps exist
- **No**: Not implemented
- **N/A**: Not applicable to this project

---

## Domain-Specific Checks

### AUTHN - Authentication & Session

- [ ] Multi-factor authentication available?
- [ ] Secure password storage (bcrypt/argon2)?
- [ ] Session timeout implemented?
- [ ] Session fixation protection?
- [ ] Account lockout policy?
- [ ] Secure credential recovery?

### AUTHZ - Authorization

- [ ] Role-based or attribute-based access control?
- [ ] Principle of least privilege applied?
- [ ] Authorization checks on all endpoints?
- [ ] Sensitive operations require re-authentication?

### INPUT - Input Validation

- [ ] All input validated server-side?
- [ ] Allowlist validation preferred?
- [ ] File upload restrictions?
- [ ] SQL injection prevention?
- [ ] Command injection prevention?

### OUTPUT - Output Encoding

- [ ] Context-aware output encoding?
- [ ] XSS prevention measures?
- [ ] Content-Type headers set correctly?
- [ ] Content Security Policy implemented?

### CRYPTO - Cryptography

- [ ] TLS 1.2+ for all connections?
- [ ] Strong cipher suites only?
- [ ] Sensitive data encrypted at rest?
- [ ] Proper key management?
- [ ] No hardcoded secrets?

### LOG - Logging & Monitoring

- [ ] Security events logged?
- [ ] Log injection prevention?
- [ ] Sensitive data masked in logs?
- [ ] Log integrity protection?
- [ ] Alerting configured?

### API - API Security

- [ ] API authentication required?
- [ ] Rate limiting implemented?
- [ ] Input validation on all endpoints?
- [ ] CORS properly configured?
- [ ] API versioning strategy?

### DATA - Data Protection

- [ ] PII identified and protected?
- [ ] Data classification implemented?
- [ ] Data retention policy?
- [ ] Secure data deletion?

---

## Gap Documentation Format

```yaml
security_gaps:
  gaps:
    - id: GAP-001
      domain: AUTHN
      description: "Multi-factor authentication not implemented"
      current_state: "Single-factor (password only)"
      expected_state: "TOTP or WebAuthn MFA available"
      impact: "Credential compromise leads to full account takeover"
      risk_level: HIGH
      affected_elements: [P-002, EP-API-001]
      kb_reference: "control-set-01-authn.md"

    - id: GAP-002
      domain: INPUT
      description: "Missing request schema validation"
      current_state: "Basic type checking only"
      expected_state: "JSON Schema validation on all API inputs"
      impact: "Malformed input may bypass security controls"
      risk_level: MEDIUM
      affected_elements: [P-001, DF-001]
      kb_reference: "control-set-03-input.md"

  design_matrix:
    AUTHN:
      assessed: true
      rating: Partial
      gaps_count: 2
    AUTHZ:
      assessed: true
      rating: Yes
      gaps_count: 0
    # ... all 16 domains
```

---

## Report Template

```markdown
# P4: Security Design Review

## Executive Summary

- **Domains Assessed**: 16
- **Fully Compliant**: N
- **Partially Compliant**: N
- **Non-Compliant**: N
- **Critical Gaps**: N

## Security Design Assessment Matrix

| Domain | Code | Implementation | Rating | Gaps | Risk | Reference |
|--------|------|----------------|--------|------|------|-----------|
| Authentication | AUTHN | OAuth2, local | Partial | 2 | High | control-set-01 |
| Authorization | AUTHZ | RBAC | Yes | 0 | Low | control-set-02 |
| ... | ... | ... | ... | ... | ... | ... |

## Gap Analysis

### GAP-001: Missing Multi-Factor Authentication

- **Domain**: AUTHN
- **Current State**: Password-only authentication
- **Expected State**: TOTP or WebAuthn MFA
- **Impact**: High - Full account takeover on credential compromise
- **Affected Elements**: P-002, EP-API-001, EP-API-002
- **Recommendation**: Implement TOTP with recovery codes

### GAP-002: ...

## Domain Details

### AUTHN - Authentication & Session

**Implementation Found**:
- OAuth2 with Google/GitHub providers
- Local authentication with bcrypt password hashing
- JWT session tokens

**Gaps Identified**:
1. No MFA support
2. Session timeout not configurable

**Recommendations**:
1. Add TOTP MFA option
2. Implement configurable session timeout

### AUTHZ - Authorization

...

## Summary

[yaml:security_gaps block]
```

---

## Completion Checklist

Before marking Phase 4 complete:

- [ ] All 16 domains assessed
- [ ] Assessment matrix complete
- [ ] All gaps documented with GAP-xxx IDs
- [ ] Risk levels assigned
- [ ] KB references provided
- [ ] Recommendations included
- [ ] Validation passed

---

**End of Phase 4 Instructions** (~200 lines, ~2K tokens)
