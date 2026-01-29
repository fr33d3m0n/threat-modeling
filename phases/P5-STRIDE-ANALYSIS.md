# Phase 5: STRIDE Threat Analysis

**Type**: Enumerative
**Executor**: LLM
**Knowledge**: CWE → CAPEC (Threat Pattern Set)

---

## Input Context

← P2/P4: `dfd_elements`, `security_gaps`

## Output Context

→ P6: `threat_inventory` {threats[], summary{}}

---

## Core Analysis Goal

Apply STRIDE method systematically to ALL DFD elements, generating a complete threat inventory. Each element must be analyzed for applicable STRIDE categories.

---

## Knowledge Reference

**Query Commands**:
```bash
$SKILL_PATH/kb --stride spoofing           # STRIDE category details
$SKILL_PATH/kb --stride tampering
$SKILL_PATH/kb --full-chain CWE-89         # Complete chain: STRIDE→CWE→CAPEC→ATT&CK
$SKILL_PATH/kb --all-llm                   # LLM-specific threats
```

---

## STRIDE per Element Matrix

| Element Type | S | T | R | I | D | E |
|--------------|---|---|---|---|---|---|
| Process      | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data Store   |   | ✓ | ✓ | ✓ | ✓ |   |
| Data Flow    |   | ✓ |   | ✓ | ✓ |   |
| External Interactor (as source) | ✓ |   | ✓ |   |   |   |

---

## STRIDE Categories

### S - Spoofing

**Definition**: Impersonating something or someone

**CWE Mapping**: CWE-287, CWE-290, CWE-307
**CAPEC Mapping**: CAPEC-151, CAPEC-194, CAPEC-600

**Questions**:
- Can an attacker impersonate another user?
- Can an attacker impersonate a system component?
- Is authentication properly implemented?

### T - Tampering

**Definition**: Modifying data or code

**CWE Mapping**: CWE-20, CWE-77, CWE-78, CWE-89
**CAPEC Mapping**: CAPEC-66, CAPEC-88, CAPEC-248

**Questions**:
- Can input data be modified?
- Can stored data be modified?
- Can data in transit be modified?

### R - Repudiation

**Definition**: Denying having performed an action

**CWE Mapping**: CWE-117, CWE-223, CWE-778
**CAPEC Mapping**: CAPEC-93

**Questions**:
- Are actions logged?
- Can logs be modified or deleted?
- Is there sufficient audit trail?

### I - Information Disclosure

**Definition**: Exposing information to unauthorized parties

**CWE Mapping**: CWE-200, CWE-209, CWE-311
**CAPEC Mapping**: CAPEC-116, CAPEC-157

**Questions**:
- Can sensitive data be accessed?
- Are error messages revealing?
- Is data encrypted properly?

### D - Denial of Service

**Definition**: Making a resource unavailable

**CWE Mapping**: CWE-400, CWE-770, CWE-918
**CAPEC Mapping**: CAPEC-125, CAPEC-227

**Questions**:
- Can the service be overwhelmed?
- Are there resource limits?
- Can an attacker exhaust resources?

### E - Elevation of Privilege

**Definition**: Gaining unauthorized capabilities

**CWE Mapping**: CWE-269, CWE-284, CWE-862
**CAPEC Mapping**: CAPEC-122, CAPEC-233

**Questions**:
- Can a user gain admin privileges?
- Are authorization checks complete?
- Can an attacker escape sandbox?

---

## Threat ID Format

```
T-{STRIDE}-{ElementID}-{Seq}
```

- **STRIDE**: Single letter (S/T/R/I/D/E)
- **ElementID**: From P2 (e.g., P-001, DS-001, DF-001)
- **Seq**: Three-digit sequence (001-999)

**Examples**:
- `T-S-P-001-001` - First Spoofing threat for Process 001
- `T-T-DF-003-002` - Second Tampering threat for Data Flow 003
- `T-I-DS-001-001` - First Info Disclosure threat for Data Store 001

---

## Analysis Process

For each DFD element:

1. **Identify applicable STRIDE categories** (per matrix above)
2. **For each applicable category**:
   - Describe the threat scenario
   - Identify related CWE
   - Map to CAPEC if available
   - Assess initial priority

3. **Document in threat inventory**

---

## Threat Inventory Structure

```yaml:threat_inventory
threats:
  - id: T-S-P-001-001
    element_id: P-001
    element_name: "API Gateway"
    stride_type: S
    stride_name: Spoofing
    title: "Authentication Bypass via Token Manipulation"
    description: |
      An attacker could forge or manipulate JWT tokens to impersonate
      legitimate users or bypass authentication entirely.
    attack_scenario: |
      1. Attacker obtains a valid JWT token
      2. Modifies token payload (user_id, role)
      3. Server accepts modified token due to weak verification
    affected_flows: [DF-001, DF-002]
    affected_stores: []
    cwe: CWE-287
    capec: CAPEC-194
    initial_priority: P1
    likelihood: HIGH
    impact: HIGH

  - id: T-T-DS-001-001
    element_id: DS-001
    element_name: "User Database"
    stride_type: T
    stride_name: Tampering
    title: "SQL Injection in User Lookup"
    description: |
      User input in login query may allow SQL injection, enabling
      attackers to modify database contents.
    attack_scenario: |
      1. Attacker enters malicious input in username field
      2. Input concatenated into SQL query
      3. Attacker modifies or extracts database data
    affected_flows: [DF-003]
    affected_stores: [DS-001]
    cwe: CWE-89
    capec: CAPEC-66
    initial_priority: P0
    likelihood: MEDIUM
    impact: CRITICAL

summary:
  total: 85
  by_stride:
    S: 12
    T: 18
    R: 8
    I: 22
    D: 10
    E: 15
  by_element_type:
    process: 45
    datastore: 20
    dataflow: 15
    external: 5
  by_priority:
    P0: 5
    P1: 15
    P2: 35
    P3: 30
```

---

## Priority Classification

| CVSS Score | Priority | Action |
|------------|----------|--------|
| 9.0 - 10.0 | P0 | Immediate fix |
| 7.0 - 8.9 | P1 | Fix within 24h |
| 4.0 - 6.9 | P2 | Fix within 7d |
| 0.1 - 3.9 | P3 | Plan within 30d |

---

## Report Template

```markdown
# P5: STRIDE Threat Analysis

## Threat Summary

| Metric | Count |
|--------|-------|
| Total Threats | N |
| Critical (P0) | N |
| High (P1) | N |
| Medium (P2) | N |
| Low (P3) | N |

## STRIDE Distribution

| Category | Count | Percentage |
|----------|-------|------------|
| Spoofing | N | N% |
| Tampering | N | N% |
| Repudiation | N | N% |
| Information Disclosure | N | N% |
| Denial of Service | N | N% |
| Elevation of Privilege | N | N% |

## Element Coverage

| Element | Type | Threats |
|---------|------|---------|
| P-001 | Process | T-S-P-001-001, T-T-P-001-001, ... |
| DS-001 | Data Store | T-T-DS-001-001, T-I-DS-001-001, ... |
| DF-001 | Data Flow | T-T-DF-001-001, T-I-DF-001-001, ... |

## Threat Details

### T-S-P-001-001: Authentication Bypass via Token Manipulation

- **Element**: P-001 (API Gateway)
- **STRIDE**: Spoofing
- **CWE**: CWE-287
- **CAPEC**: CAPEC-194
- **Priority**: P1
- **Description**: ...
- **Attack Scenario**: ...

### T-T-DS-001-001: SQL Injection in User Lookup

...

## Threat Inventory

[yaml:threat_inventory block]
```

---

## Validation Gates

| Check | Severity |
|-------|----------|
| yaml:threat_inventory block present | BLOCKING |
| All DFD elements have associated threats | BLOCKING |
| Threat count per element >= 2 | WARNING |
| CWE mapping provided for each threat | WARNING |
| Summary totals match threat list | BLOCKING |

---

## Completion Checklist

Before marking Phase 5 complete:

- [ ] All Processes analyzed for S,T,R,I,D,E
- [ ] All Data Stores analyzed for T,R,I,D
- [ ] All Data Flows analyzed for T,I,D
- [ ] All External Interactors analyzed for S,R
- [ ] yaml:threat_inventory block present
- [ ] Summary totals correct
- [ ] CWE/CAPEC mappings provided
- [ ] Validation passed

---

**End of Phase 5 Instructions** (~250 lines, ~2K tokens)
