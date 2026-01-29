<!-- Code-First Deep Threat Modeling Workflow | Version 3.0.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause -->

---
name: threat-modeling
description: |
  Code-first automated threat modeling toolkit with 8-phase sequential workflow.

  Phases: Project Understanding → DFD Analysis → Trust Boundaries → Security Design →
          STRIDE Analysis → Risk Validation → Mitigation Planning → Report Generation

  Each phase requires validation (exit 0) before proceeding to next.

  Use when: threat model, STRIDE, DFD, security assessment, 威胁建模, 安全评估.
hooks:
  PostToolUse:
    - matcher: "Write"
      hooks:
        - type: command
          command: "./hooks/phase_end_hook.sh"
          timeout: 30
---

# Code-First Deep Risk Analysis v3.0.0

Code-first automated deep threat modeling with comprehensive security chain analysis.

## Version Banner

```
════════════════════════════════════════════════════════════════════════════════
  🛡️ STRIDE Threat Modeling Skill v3.0.0
════════════════════════════════════════════════════════════════════════════════
```

**Version Format**: `vX.Y.Z` — Semantic versioning

---

## §1 Execution Model

**Mode**: Full Assessment Only - All 8 phases executed sequentially.

```
Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► Phase 6 ──► Phase 7 ──► Phase 8
Project     Call Flow    Trust      Security    STRIDE      Risk        Mitigation   Report
Understanding  DFD      Boundaries   Design     Analysis   Validation
```

**Rules**:
1. Phases execute strictly in order (1→8)
2. Each phase output passes to next phase as input
3. Each phase requires validation (exit 0) before completion
4. Phase 6 = Risk Validation (NOT mitigation)
5. Phase 7 = Mitigation Planning (AFTER validation)

**Phase Gate Protocol**:
```
FOR each phase N in [1..8]:
    1. Read: @phases/P{N}-*.md
    2. Execute analysis per phase instructions
    3. Write output to .phase_working/P{N}-*.md
    4. Hook auto-triggers: phase_data.py --phase-end --phase {N}
    5. IF exit != 0: Fix errors, rewrite phase output
    6. IF exit == 0: Mark complete, continue to N+1
```

---

## §2 Output Convention

### Directory Structure

```
{PROJECT_ROOT}/
└── Risk_Assessment_Report/
    ├── {PROJECT}-RISK-ASSESSMENT-REPORT.md    ← Main report
    ├── {PROJECT}-RISK-INVENTORY.md            ← Risk inventory
    ├── {PROJECT}-MITIGATION-MEASURES.md       ← Mitigations
    ├── {PROJECT}-PENETRATION-TEST-PLAN.md     ← Pentest plan
    ├── {PROJECT}-ARCHITECTURE-ANALYSIS.md     ← Architecture
    ├── {PROJECT}-DFD-DIAGRAM.md               ← DFD
    ├── {PROJECT}-COMPLIANCE-REPORT.md         ← Compliance
    ├── {PROJECT}-ATTACK-PATH-VALIDATION.md    ← Attack paths
    ├── P1-PROJECT-UNDERSTANDING.md            ← Phase outputs
    ├── P2-DFD-ANALYSIS.md
    ├── P3-TRUST-BOUNDARY.md
    ├── P4-SECURITY-DESIGN-REVIEW.md
    ├── P5-STRIDE-THREATS.md
    ├── P6-RISK-VALIDATION.md
    └── .phase_working/                        ← Working directory
        └── _session_meta.yaml
```

### Naming Convention

- **PROJECT**: Uppercase, max 30 chars, format: `^[A-Z][A-Z0-9-]{0,29}$`
- **Example**: `OPEN-WEBUI`, `MY-PROJECT`, `STRIDE-DEMO`

### Session Metadata

```yaml
# _session_meta.yaml
session_id: "YYYYMMDD-HHMMSS"
project_name: "OPEN-WEBUI"
project_path: "/path/to/project"
started_at: "ISO8601 timestamp"
phases_completed: [1, 2, 3]
current_phase: 4
skill_version: "3.0.0"
```

---

## §3 Core Data Model

> See @contracts/data-model.yaml for complete schema definitions.

### Entity Types

| Entity | ID Format | Phase | Description |
|--------|-----------|-------|-------------|
| Module | M-{Seq:03d} | P1 | Code modules/components |
| Finding | F-P{N}-{Seq:03d} | P1-P4 | Security observations |
| Threat | T-{STRIDE}-{Element}-{Seq} | P5 | STRIDE threats |
| ValidatedRisk | VR-{Seq:03d} | P6 | Verified risks |
| Mitigation | MIT-{Seq:03d} | P7 | Remediation measures |
| POC | POC-{Seq:03d} | P6 | Proof of concept |
| AttackPath | AP-{Seq:03d} | P6 | Attack paths |

### DFD Element IDs

| Element Type | Prefix | Format | Example |
|--------------|--------|--------|---------|
| External Interactor | EI | EI-{NNN} | EI-001 |
| Process | P | P-{NNN} | P-001 |
| Data Store | DS | DS-{NNN} | DS-001 |
| Data Flow | DF | DF-{NNN} | DF-001 |
| Trust Boundary | TB | TB-{NNN} | TB-001 |

### Count Conservation

```
P5.threat_count = P6.verified + P6.theoretical + P6.pending + P6.excluded
```

All threats must be accounted for in Phase 6.

---

## §4 Security Knowledge Architecture

> See @knowledge/ for complete reference materials.

### Three Knowledge Sets

1. **Security Control Set** (What to do)
   - 16 Security Domains (AUTHN, AUTHZ, INPUT, etc.)
   - Control Sets (18 files, 107 controls)
   - OWASP References (74 items)
   - Compliance Frameworks (14 frameworks)

2. **Threat Pattern Set** (What to know)
   - CWE Weaknesses (974)
   - CAPEC Attack Patterns (615)
   - ATT&CK Techniques (835)
   - CVE/KEV Vulnerabilities (323K+)

3. **Verification Set** (How to test)
   - WSTG Tests (121)
   - MASTG Tests (206)
   - ASVS Requirements (345)

### Security Principles (11)

| Code | Principle | Definition |
|------|-----------|------------|
| DID | Defense in Depth | Multiple independent security controls |
| LP | Least Privilege | Minimum permissions required |
| ZT | Zero Trust | Never trust, always verify |
| FS | Fail Secure | Default to secure state on error |
| SOD | Separation of Duties | Critical ops require multiple parties |
| SBD | Secure by Default | Default config is secure |
| CM | Complete Mediation | Every access verified |
| EOM | Economy of Mechanism | Simple, auditable mechanisms |
| OD | Open Design | Security not dependent on secrecy |
| IV | Input Validation | All input validated |
| LA | Least Agency | Limit AI agent autonomy |

### STRIDE Categories

| STRIDE | Name | CWEs | CAPEC |
|--------|------|------|-------|
| S | Spoofing | CWE-287, 290, 307 | CAPEC-151, 194, 600 |
| T | Tampering | CWE-20, 77, 78, 89 | CAPEC-66, 88, 248 |
| R | Repudiation | CWE-117, 223, 778 | CAPEC-93 |
| I | Information Disclosure | CWE-200, 209, 311 | CAPEC-116, 157 |
| D | Denial of Service | CWE-400, 770, 918 | CAPEC-125, 227 |
| E | Elevation of Privilege | CWE-269, 284, 862 | CAPEC-122, 233 |

---

## §5 Knowledge Base Queries

### kb Wrapper Usage

```bash
# Get skill path
SKILL_PATH=$(bash skill_path.sh)

# STRIDE queries
$SKILL_PATH/kb --stride spoofing
$SKILL_PATH/kb --stride-controls S

# CWE queries
$SKILL_PATH/kb --cwe CWE-89
$SKILL_PATH/kb --full-chain CWE-89

# Attack patterns
$SKILL_PATH/kb --capec CAPEC-89
$SKILL_PATH/kb --attack-technique T1078

# Verification tests
$SKILL_PATH/kb --stride-tests S
$SKILL_PATH/kb --wstg-category ATHN

# LLM/AI extensions
$SKILL_PATH/kb --all-llm
$SKILL_PATH/kb --ai-component
```

---

## §6 Language Adaptation

Output language follows context language unless `--lang=xx` specified.

| Context | File Names | Content |
|---------|------------|---------|
| Chinese | P1-项目理解.md | 中文 |
| English | P1-PROJECT-UNDERSTANDING.md | English |

Supported: en, zh, ja, ko, es, fr, de, pt, ru

---

## §7 Progressive Context Loading

This skill uses progressive disclosure:

1. **Always Loaded**: This file (SKILL.md) - ~5K tokens
2. **Session Start**: @WORKFLOW.md - ~3K tokens
3. **Per Phase**: @phases/P{N}-*.md - ~2K tokens each

Total per-phase context: ~10K tokens (vs 30K monolithic)

**Loading Pattern**:
```
Session Start:
  1. Load SKILL.md (global rules)
  2. Load WORKFLOW.md (orchestration)
  3. Create 8 phase todos

Per Phase:
  1. Read @phases/P{N}-*.md
  2. Execute phase instructions
  3. Write to .phase_working/P{N}-*.md
  4. Hook validates and extracts data
```

---

## §8 Reference Files

| Path | Purpose |
|------|---------|
| @WORKFLOW.md | Orchestration contracts, phase gates |
| @phases/P{1-8}-*.md | Phase-specific instructions |
| @contracts/data-model.yaml | Entity schemas |
| @contracts/phase-output.schema.yaml | Output validation schemas |
| @knowledge/security-design.yaml | 16 security domains |
| @knowledge/security-principles.yaml | 11 security principles |
| @scripts/phase_data.py | Phase validation and extraction |
| @scripts/unified_kb_query.py | Knowledge base queries |
| @hooks/phase_end_hook.sh | PostToolUse automation |

---

## §9 Quick Start

```bash
# 1. Start new session
# Claude loads SKILL.md + WORKFLOW.md automatically

# 2. For each phase N (1-8):
#    a. Read phase instructions
Read @phases/P{N}-*.md

#    b. Execute analysis and write output
Write .phase_working/P{N}-*.md

#    c. Hook auto-validates (PostToolUse)
# If validation fails, fix and rewrite

# 3. Generate final reports in Risk_Assessment_Report/
```

---

**End of SKILL.md** (~400 lines, ~5K tokens)
