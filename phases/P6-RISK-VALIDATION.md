# Phase 6: Risk Validation

**Type**: Verification
**Executor**: LLM
**Knowledge**: CAPEC → ATT&CK → CVE/KEV, WSTG, MASTG

---

## Input Context

← ALL P1-P5: findings_1 + findings_2 + findings_3 + findings_4 + findings_5

**CRITICAL**: Phase 6 consolidates ALL previous findings, not just Phase 5 threats.

## Output Context

→ P7: `validated_risks` {risk_summary{}, risk_details[], poc_details[], attack_paths[], attack_chains[]}

---

## Core Analysis Goal

Consolidate ALL findings from P1-P5, perform deep validation from attacker's perspective, design attack paths and POC code. This is NOT mitigation - focus on VALIDATING that risks are exploitable.

---

## Knowledge Reference

**Query Commands**:
```bash
# Attack path analysis
$SKILL_PATH/kb --capec CAPEC-89 --attack-chain
$SKILL_PATH/kb --attack-technique T1078
$SKILL_PATH/kb --check-kev CVE-2024-XXXX

# Verification tests
$SKILL_PATH/kb --stride-tests S
$SKILL_PATH/kb --cwe-tests CWE-89
$SKILL_PATH/kb --wstg-category ATHN
```

---

## Consolidation Process

### Step 1: Gather All Findings

| Source | Finding Types | ID Format |
|--------|---------------|-----------|
| P1 | Module/Entry discoveries | F-P1-xxx |
| P2 | DFD issues | F-P2-xxx |
| P3 | Boundary issues | F-P3-xxx |
| P4 | Security gaps | GAP-xxx |
| P5 | STRIDE threats | T-xxx |

### Step 2: Deduplicate and Merge

Similar threats targeting the same vulnerability should be merged into a single ValidatedRisk with multiple `threat_refs`.

### Step 3: Validate Each Risk

For each potential risk:
1. **Assess exploitability**: Can it actually be exploited?
2. **Design attack path**: What steps would an attacker take?
3. **Create POC**: How would exploitation work?
4. **Determine status**: verified/theoretical/pending/excluded

---

## Verification Status Types

| Status | Symbol | Meaning | Criteria |
|--------|--------|---------|----------|
| verified | ✅ | POC executed successfully | Attack reproduced |
| pending | ⚠️ | Needs manual verification | Requires specific environment |
| theoretical | 📋 | Code analysis shows exploitable | Not yet tested |
| excluded | ❌ | Confirmed not exploitable | Mitigations exist |

---

## Count Conservation Rule

```
P5.threat_inventory.total = verified + theoretical + pending + excluded
```

**Every threat from P5 MUST be accounted for in P6**:
- Either in a ValidatedRisk's `threat_refs[]`
- Or marked as `excluded` with documented reason

---

## Output Structure (5 Parts)

### Part 1: Risk Summary

```yaml
risk_summary:
  total_identified: 85          # From P5
  total_verified: 12            # ✅ POC confirmed
  total_pending: 8              # ⚠️ Needs verification
  total_theoretical: 45         # 📋 Code analysis
  total_excluded: 20            # ❌ Not exploitable
  verification_rate: "76%"      # (verified+theoretical)/total
  risk_by_severity:
    critical: 5
    high: 12
    medium: 25
    low: 23
  risk_by_stride:
    S: 12
    T: 18
    R: 8
    I: 22
    D: 10
    E: 15
```

### Part 2: POC Details

Every Critical/High threat MUST have a complete POC:

```yaml
poc_details:
  - poc_id: POC-001
    threat_ref: T-S-P-001-001
    stride_type: S
    verification_status: verified
    exploitation_difficulty: medium
    prerequisites:
      - "Valid user session"
      - "Knowledge of target user ID"
    vulnerability_location:
      file_path: "src/api/auth.py"
      function_name: "verify_token"
      line_number: 45
    vulnerable_code: |
      def verify_token(token):
          # Missing signature verification
          return jwt.decode(token, options={"verify_signature": False})
    exploitation_steps:
      - "Obtain any valid JWT token"
      - "Modify payload to change user_id"
      - "Send modified token to API"
    poc_code: |
      import jwt
      import requests

      # 1. Get valid token
      original_token = "eyJ..."

      # 2. Decode without verification
      payload = jwt.decode(original_token, options={"verify_signature": False})

      # 3. Modify user_id
      payload["user_id"] = "admin"

      # 4. Re-encode (any key works)
      malicious_token = jwt.encode(payload, "any_key", algorithm="HS256")

      # 5. Use malicious token
      response = requests.get(
          "https://target.com/api/user/profile",
          headers={"Authorization": f"Bearer {malicious_token}"}
      )
      print(response.json())
    expected_result: |
      {"status": "success", "user": {"id": "admin", "role": "administrator"}}
    actual_result: |
      Successfully retrieved admin profile
    risk_assessment:
      complexity: medium
      attack_vector: network
      impact_scope: user_data
      data_sensitivity: high
```

### Part 3: Risk Details

```yaml
risk_details:
  - risk_id: VR-001
    title: "JWT Signature Verification Bypass"
    threat_refs: [T-S-P-001-001, T-E-P-001-002]  # MANDATORY
    finding_refs: [GAP-001]
    stride_types: [S, E]
    priority: P0
    cvss_score: 9.8
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    location:
      files: ["src/api/auth.py"]
      elements: [P-001]
      trust_boundary: TB-001
    detailed_analysis: |
      The application uses PyJWT to decode tokens but disables
      signature verification, allowing attackers to forge tokens.
    root_cause: |
      Developer explicitly disabled verification for "debugging"
      and forgot to re-enable it.
    related_cwe: CWE-287
    related_capec: CAPEC-194
    related_attack: T1078
    related_poc: POC-001
    validation:
      status: verified
      poc_available: true
      test_cases:
        - "WSTG-ATHN-04: JWT Token Forgery"
```

### Part 4: Attack Path Matrix

```yaml
attack_path_matrix:
  - path_id: AP-001
    path_name: "Auth Bypass → Admin Access"
    entry_point: "Public API"
    key_nodes: [P-001, P-002]
    final_target: "Admin Functions"
    feasibility_score: 9.2
    detection_difficulty: low
    priority_fix: true
    related_risks: [VR-001]

  - path_id: AP-002
    path_name: "SQL Injection → Data Exfiltration"
    entry_point: "Search API"
    key_nodes: [P-003, DS-001]
    final_target: "User Database"
    feasibility_score: 7.5
    detection_difficulty: medium
    priority_fix: true
    related_risks: [VR-003]
```

### Part 5: Attack Chains

```yaml
attack_chains:
  - chain_id: AC-001
    chain_name: "Privilege Escalation Chain"
    entry_point: "Public API"
    target: "Administrator Access"
    impact_scope: "Complete System Control"
    difficulty: medium
    related_threats: [T-S-P-001-001, T-E-P-001-002]
    steps:
      - step: 1
        title: "Initial Access"
        source: "Attacker"
        target: "API Gateway"
        action: "Obtain valid JWT token"
        code_location: "api/routes.py:120"
        data_change: "Acquire session token"
      - step: 2
        title: "Token Manipulation"
        source: "Attacker"
        target: "JWT Token"
        action: "Modify user_id in payload"
        code_location: "N/A (client-side)"
        data_change: "Forged admin identity"
      - step: 3
        title: "Privilege Escalation"
        source: "API Gateway"
        target: "Auth Service"
        action: "Submit forged token"
        code_location: "auth/verify.py:45"
        data_change: "Gain admin role"
    attack_flow_diagram: |
      ┌─────────────────────────────────────────────────────────────────┐
      │                 Attack Chain: Privilege Escalation               │
      ├─────────────────────────────────────────────────────────────────┤
      │  Step 1: Initial Access                                          │
      │  ┌───────────────────────────────────────────────────────────┐  │
      │  │  Attacker ──→ API Gateway                                  │  │
      │  │  Action: Obtain valid JWT token                            │  │
      │  │  Location: api/routes.py:120                               │  │
      │  └───────────────────────────────────────────────────────────┘  │
      │                              │                                   │
      │                              ▼                                   │
      │  Step 2: Token Manipulation                                      │
      │  ┌───────────────────────────────────────────────────────────┐  │
      │  │  Attacker ──→ JWT Token                                    │  │
      │  │  Action: Modify user_id in payload                         │  │
      │  │  Location: Client-side manipulation                        │  │
      │  └───────────────────────────────────────────────────────────┘  │
      │                              │                                   │
      │                              ▼                                   │
      │  Step 3: Privilege Escalation                                    │
      │  ┌───────────────────────────────────────────────────────────┐  │
      │  │  API Gateway ──→ Auth Service                              │  │
      │  │  Action: Submit forged token, gain admin role              │  │
      │  │  Location: auth/verify.py:45                               │  │
      │  └───────────────────────────────────────────────────────────┘  │
      │                              │                                   │
      │                              ▼                                   │
      │  Result: Administrator access achieved                           │
      └─────────────────────────────────────────────────────────────────┘
    prerequisites:
      - "Network access to API"
      - "Ability to create user account"
    exploitation_commands: |
      # Step 1: Get valid token
      TOKEN=$(curl -s -X POST https://target/api/login \
        -d '{"user":"test","pass":"test123"}' | jq -r '.token')

      # Step 2: Forge admin token
      ADMIN_TOKEN=$(python3 jwt_forge.py --token $TOKEN --user admin)

      # Step 3: Access admin functions
      curl -H "Authorization: Bearer $ADMIN_TOKEN" \
        https://target/api/admin/users
    ioc_indicators:
      - "JWT tokens with mismatched signature"
      - "Rapid role changes in same session"
    defense_recommendations:
      - cutpoint: "Step 2"
        recommendation: "Enable JWT signature verification"
      - cutpoint: "Step 3"
        recommendation: "Implement token binding to IP/device"
```

---

## Report Template

```markdown
# P6: Risk Validation

## Executive Summary

| Metric | Count |
|--------|-------|
| Total Threats (from P5) | N |
| Verified (✅) | N |
| Pending (⚠️) | N |
| Theoretical (📋) | N |
| Excluded (❌) | N |
| Verification Rate | N% |

## Count Conservation Check

- P5 Total: N
- P6 Total (V+Th+P+E): N
- Status: ✅ PASS / ❌ FAIL

## Critical Risks

### VR-001: JWT Signature Verification Bypass

[Full risk detail with POC]

## Attack Path Analysis

### AP-001: Auth Bypass → Admin Access

[Attack path with feasibility score]

## Attack Chains

### AC-001: Privilege Escalation Chain

[Full attack chain with ASCII diagram]

## Validated Risks Inventory

[yaml:validated_risks block]
```

---

## Validation Gates

| Check | Severity |
|-------|----------|
| yaml:validated_risks block present | BLOCKING |
| Count conservation formula balances | BLOCKING |
| Critical/High risks have POC details | BLOCKING |
| attack_chains section present | WARNING |
| ASCII diagrams in attack chains | WARNING |

---

## Completion Checklist

Before marking Phase 6 complete:

- [ ] All P5 threats accounted for
- [ ] Count conservation verified
- [ ] yaml:validated_risks present
- [ ] yaml:poc_details for Critical/High
- [ ] yaml:attack_chains present
- [ ] ASCII attack flow diagrams included
- [ ] Validation passed

---

**End of Phase 6 Instructions** (~400 lines, ~3K tokens)
