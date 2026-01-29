# Phase 3: Trust Boundary Evaluation

**Type**: Evaluative
**Executor**: LLM
**Knowledge**: Security Principles (ZT, SOD, LP), security-design.yaml

---

## Input Context

← P1/P2: `project_context`, `dfd_elements`

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

## Trust Boundary Types

| Type | Description | Example |
|------|-------------|---------|
| Network | Network segment boundaries | Internet/DMZ, DMZ/Internal |
| Process | Process isolation boundaries | Container, VM, Sandbox |
| User | User privilege boundaries | Anonymous/Authenticated, User/Admin |
| Data | Data sensitivity boundaries | Public/Internal/Confidential |
| Service | Service trust boundaries | Internal/External services |

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

## Boundary Issues Identified

1. ...
2. ...

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
- [ ] Boundary issues documented
- [ ] Validation passed

---

**End of Phase 3 Instructions** (~200 lines, ~1.5K tokens)
