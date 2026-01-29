# Phase 8: Report Generation

**Type**: Comprehensive
**Executor**: LLM
**Knowledge**: Compliance Frameworks, ASVS

---

## Input Context

← P1-P7: ALL preceding phase outputs

**CRITICAL**: Phase 8 MUST read all phase files and aggregate content completely - do NOT summarize from memory!

## Output Context

→ Final Reports: 8 mandatory reports + phase outputs

---

## Core Analysis Goal

Synthesize all phase outputs into complete threat model documentation. Every finding, threat, risk, and mitigation from previous phases must be included - no omission.

---

## Knowledge Reference

**Query Commands**:
```bash
$SKILL_PATH/kb --compliance nist-csf
$SKILL_PATH/kb --compliance iso27001
$SKILL_PATH/kb --asvs-level L2 --chapter V1
```

---

## Report Generation Process

### Step 1: Read All Phase Outputs

```bash
# Read each phase file
.phase_working/P1-PROJECT-UNDERSTANDING.md
.phase_working/P2-DFD-ANALYSIS.md
.phase_working/P3-TRUST-BOUNDARY.md
.phase_working/P4-SECURITY-DESIGN-REVIEW.md
.phase_working/P5-STRIDE-THREATS.md
.phase_working/P6-RISK-VALIDATION.md
.phase_working/P7-MITIGATION-PLAN.md
```

### Step 2: Extract Structured Data

Use phase_data.py or manually extract:
- yaml:module_inventory from P1
- yaml:dfd_elements from P2
- yaml:threat_inventory from P5
- yaml:validated_risks from P6
- yaml:mitigation_plan from P7

### Step 3: Generate Reports

Create all 8 mandatory reports in `Risk_Assessment_Report/`

---

## Required Reports (8)

| # | Report | Content Source |
|---|--------|----------------|
| 1 | RISK-ASSESSMENT-REPORT.md | All phases synthesis |
| 2 | RISK-INVENTORY.md | P6 validated_risks |
| 3 | MITIGATION-MEASURES.md | P7 mitigation_plan |
| 4 | PENETRATION-TEST-PLAN.md | P6 POCs + test cases |
| 5 | ARCHITECTURE-ANALYSIS.md | P1-P3 synthesis |
| 6 | DFD-DIAGRAM.md | P2 DFD content |
| 7 | COMPLIANCE-REPORT.md | P4 + frameworks |
| 8 | ATTACK-PATH-VALIDATION.md | P6 attack chains |

---

## Report 1: Main Risk Assessment Report

**File**: `{PROJECT}-RISK-ASSESSMENT-REPORT.md`

### Structure (9 Sections)

```markdown
# {PROJECT} Risk Assessment Report

**Generated**: {timestamp}
**Skill Version**: 3.0.0
**Assessment Scope**: {project_path}

---

## 1. Executive Summary

### Key Findings
- **Total Risks Identified**: N
- **Critical (P0)**: N - Require immediate attention
- **High (P1)**: N - Fix within 24-48 hours
- **Medium (P2)**: N - Plan within 7 days
- **Low (P3)**: N - Backlog for 30 days

### Top 3 Critical Risks
1. VR-001: {title} - CVSS {score}
2. VR-002: {title} - CVSS {score}
3. VR-003: {title} - CVSS {score}

### Recommendations Summary
{High-level recommendations}

---

## 2. System Architecture Overview

{From P1: Project structure, modules, entry points}
{From P2: DFD summary}
{From P3: Trust boundary summary}

### Architecture Diagram
[ASCII or Mermaid diagram]

### Key Components
| Component | Type | Security Relevance |
|-----------|------|-------------------|
| {name} | {type} | {relevance} |

---

## 3. Security Design Assessment

{From P4: Complete security_gaps content}

### Assessment Matrix
| Domain | Rating | Gaps | Risk Level |
|--------|--------|------|------------|
| AUTHN | Partial | 2 | High |
| ... | ... | ... | ... |

### Critical Security Gaps
{Detailed gap descriptions}

---

## 4. STRIDE Threat Analysis

{From P5: Complete threat_inventory content}

### Threat Distribution
| STRIDE | Count | Critical | High | Medium | Low |
|--------|-------|----------|------|--------|-----|
| S | N | N | N | N | N |
| ... | ... | ... | ... | ... | ... |

### Threat Coverage
{Element-by-element threat mapping}

---

## 5. Risk Validation & POC Design ← CRITICAL SECTION

{From P6: Complete poc_details content - DO NOT SUMMARIZE}

### Validated Risks
{Full VR-xxx details with POC code}

### POC Summary
| POC ID | Risk | Status | Difficulty |
|--------|------|--------|------------|
| POC-001 | VR-001 | ✅ Verified | Medium |

---

## 6. Attack Path Analysis ← CRITICAL SECTION

{From P6: Complete attack_chains content - DO NOT SUMMARIZE}

### Attack Chain: {name}
[ASCII attack flow diagram]

### Feasibility Matrix
| Path ID | Entry | Target | Score | Priority |
|---------|-------|--------|-------|----------|
| AP-001 | API | Admin | 9.2 | Yes |

---

## 7. Threat Priority Matrix

### By Severity
| Priority | Count | Examples |
|----------|-------|----------|
| P0 | N | VR-001, VR-002 |
| P1 | N | VR-003, VR-004 |

### By STRIDE Category
{Distribution chart}

---

## 8. Mitigation Recommendations ← CRITICAL SECTION

{From P7: Complete mitigation_plan content - DO NOT SUMMARIZE}

### Immediate Actions (P0)
{Full MIT-xxx details with code}

### Implementation Roadmap
| Timeline | Actions | Owner |
|----------|---------|-------|
| Immediate | MIT-001, MIT-002 | Security |
| 7 days | MIT-003, MIT-004 | Backend |

---

## 9. Compliance Mapping

### Framework Coverage
| Framework | Coverage | Gaps |
|-----------|----------|------|
| OWASP Top 10 | 80% | A03, A07 |
| ASVS L2 | 65% | V3, V4 |
| ISO 27001 | 70% | A.12, A.14 |

### Gap Analysis
{Per-framework gap details}

---

## Appendices

### A. Complete Risk Inventory
See: {PROJECT}-RISK-INVENTORY.md

### B. Detailed Mitigations
See: {PROJECT}-MITIGATION-MEASURES.md

### C. DFD Diagrams
See: {PROJECT}-DFD-DIAGRAM.md

### D. Phase Working Documents
- P1-PROJECT-UNDERSTANDING.md
- P2-DFD-ANALYSIS.md
- P3-TRUST-BOUNDARY.md
- P4-SECURITY-DESIGN-REVIEW.md
- P5-STRIDE-THREATS.md
- P6-RISK-VALIDATION.md
```

---

## Report 2: Risk Inventory

**File**: `{PROJECT}-RISK-INVENTORY.md`

```markdown
# {PROJECT} Risk Inventory

## Summary Statistics
| Metric | Value |
|--------|-------|
| Total Risks | N |
| Critical | N |
| High | N |
| Medium | N |
| Low | N |

## Risk Listing

### VR-001: {title}
- **Priority**: P0
- **CVSS**: 9.8
- **STRIDE**: S, E
- **CWE**: CWE-287
- **Location**: src/api/auth.py:45
- **Description**: {description}
- **Threat Refs**: T-S-P-001-001, T-E-P-001-002
- **Mitigation**: MIT-001

### VR-002: {title}
...
```

---

## Report 3: Mitigation Measures

**File**: `{PROJECT}-MITIGATION-MEASURES.md`

Complete P7 content with implementation details.

---

## Report 4: Penetration Test Plan

**File**: `{PROJECT}-PENETRATION-TEST-PLAN.md`

```markdown
# {PROJECT} Penetration Test Plan

## Scope
{From P1: entry points, modules}

## Test Cases

### TC-001: JWT Token Forgery
- **Risk**: VR-001
- **POC**: POC-001
- **Prerequisites**: {list}
- **Steps**: {exploitation steps}
- **Expected Result**: {expected outcome}
- **Verification**: {how to verify}

### TC-002: SQL Injection
...

## Tools Required
- Burp Suite
- sqlmap
- jwt_tool

## Test Environment
{Environment requirements}
```

---

## Report 5: Architecture Analysis

**File**: `{PROJECT}-ARCHITECTURE-ANALYSIS.md`

Synthesis of P1-P3 content.

---

## Report 6: DFD Diagram

**File**: `{PROJECT}-DFD-DIAGRAM.md`

P2 DFD content with Mermaid source.

---

## Report 7: Compliance Report

**File**: `{PROJECT}-COMPLIANCE-REPORT.md`

P4 gaps mapped to compliance frameworks.

---

## Report 8: Attack Path Validation

**File**: `{PROJECT}-ATTACK-PATH-VALIDATION.md`

Complete P6 attack chains with diagrams.

---

## Phase Output Publication

Copy from `.phase_working/` to `Risk_Assessment_Report/`:

```bash
cp .phase_working/P1-PROJECT-UNDERSTANDING.md Risk_Assessment_Report/
cp .phase_working/P2-DFD-ANALYSIS.md Risk_Assessment_Report/
cp .phase_working/P3-TRUST-BOUNDARY.md Risk_Assessment_Report/
cp .phase_working/P4-SECURITY-DESIGN-REVIEW.md Risk_Assessment_Report/
cp .phase_working/P5-STRIDE-THREATS.md Risk_Assessment_Report/
cp .phase_working/P6-RISK-VALIDATION.md Risk_Assessment_Report/
```

---

## Content Aggregation Rules

**CRITICAL**: These sections MUST include COMPLETE content from referenced phases:

| Report Section | Source | Rule |
|----------------|--------|------|
| §5 Risk Validation | P6 poc_details | Copy ALL POCs verbatim |
| §6 Attack Paths | P6 attack_chains | Copy ALL chains with diagrams |
| §8 Mitigations | P7 mitigation_plan | Copy ALL mitigations with code |

**Prohibited Actions**:
- ❌ "See P6 for details"
- ❌ "Top 3 risks shown, others omitted"
- ❌ Summarizing POC code
- ❌ Truncating attack chains

---

## Validation Gates

| Check | Severity |
|-------|----------|
| All 8 reports generated | BLOCKING |
| Main report has all 9 sections | BLOCKING |
| P6 content included completely | BLOCKING |
| P7 content included completely | BLOCKING |
| Phase outputs copied to report dir | WARNING |

---

## Completion Checklist

Before marking Phase 8 complete:

- [ ] All 8 reports created in Risk_Assessment_Report/
- [ ] Main report includes complete P6 POCs
- [ ] Main report includes complete P7 mitigations
- [ ] Attack chain diagrams included
- [ ] Phase outputs published
- [ ] _session_meta.yaml updated
- [ ] Validation passed

---

**End of Phase 8 Instructions** (~300 lines, ~2.5K tokens)
