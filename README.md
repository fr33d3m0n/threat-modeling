# STRIDE Deep Threat Modeling Skill

**Code-First Automated Threat Modeling Toolkit** | Version 2.2.1

8-Phase Serial Workflow · Dual Knowledge Base Architecture · STRIDE+CWE+CAPEC+ATT&CK Full Chain Mapping · LLM-Native Design

[Installation](#installation) · [Quick Start](#quick-start) · [Documentation](#documentation) · [中文版](README-cn.md)

---

## Overview

A comprehensive **Code-First** threat modeling toolkit for Claude Code that transforms source code analysis into actionable security insights through an 8-phase serial workflow.

### Key Features

| Feature | Description |
|---------|-------------|
| **8-Phase Serial Workflow** | Strict sequential execution ensuring maximum depth and complete coverage |
| **Dual Knowledge Base** | Core DB (969 CWE, 615 CAPEC) + CVE Extension (323K+ CVE) |
| **Full Chain Mapping** | STRIDE → CWE → CAPEC → ATT&CK → CVE/KEV intelligence chain |
| **Attack Path Validation** | CAPEC + ATT&CK attack chain mapping with POC design |
| **KB-Enhanced Mitigations** | Context-aware mitigation suggestions per threat |
| **AI/LLM Extensions** | OWASP LLM Top 10 + AI component threat coverage |
| **Parallel Sub-Agent Support** | Multi-risk parallel analysis for large projects |
| **Semantic Search** | 3,278 embeddings for intelligent threat lookup |

### Workflow Overview

```
Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► Phase 6 ──► Phase 7 ──► Phase 8
Project     Call Flow    Trust      Security    STRIDE      Risk        Mitigation   Report
Understanding  DFD      Boundaries   Design     Analysis   Validation
```

---

## Installation

### Installation Options

```
┌─────────────────────────────────────────────────────────────┐
│                 How to Choose Installation?                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Personal use, share across projects  ──────►  Global       │
│                                        ~/.claude/skills/     │
│                                                              │
│  Team collaboration, version control  ──────►  Project-local│
│                                        project/.claude/skills│
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### System Requirements

```
Python 3.8+  |  PyYAML >= 6.0
```

### Option 1: Global Installation (Available to All Projects)

```bash
# Copy to Claude Code global skills directory
cp -r threat-modeling ~/.claude/skills/threat-modeling

# Install dependencies
pip install pyyaml
```

### Option 2: Project-Local Installation (Current Project Only)

```bash
# Create .claude/skills directory in project root
mkdir -p /path/to/your-project/.claude/skills

# Copy skill to project local
cp -r threat-modeling /path/to/your-project/.claude/skills/threat-modeling

# Install dependencies
pip install pyyaml
```

**Installation Comparison**:

| Method | Path | Scope |
|--------|------|-------|
| Global | `~/.claude/skills/` | All projects |
| Project-local | `project/.claude/skills/` | Current project only |

> **Recommendation**: For team-shared security assessment projects, use project-local installation so the skill can be version controlled with project code.

### Verify Installation

```bash
python scripts/unified_kb_query.py --all-stride --pretty
```

### Directory Structure

```
threat-modeling/
├── SKILL.md              # ← Claude Code entry point (8-phase workflow)
├── WORKFLOW.md           # Detailed workflow templates
├── scripts/              # Tool scripts
│   ├── list_files.py         # Phase 1: Project structure analysis
│   ├── stride_matrix.py      # Phase 5: STRIDE matrix
│   └── unified_kb_query.py   # Phase 5/6/7: Unified KB query
└── assets/knowledge/            # Dual database knowledge system (317MB)
    ├── security_kb.sqlite        # Core DB (13MB)
    └── security_kb_extension.sqlite  # CVE extension (304MB)
```

---

## Quick Start

### Using in Claude Code

#### Auto-Activation

The skill automatically activates when you mention these keywords:

| English | Chinese |
|---------|---------|
| threat model | 威胁建模 |
| security assessment | 安全评估 |
| DFD / data flow diagram | 数据流图 |
| trust boundary | 信任边界 |
| attack surface | 攻击面 |
| STRIDE analysis | STRIDE 分析 |

#### Usage Examples

**Threat Modeling**
```
User: Help me threat model @/path/to/project

Claude: [Auto-activates skill]
        Phase 1: Analyzing project structure...
        Phase 2: Building DFD...
        Phase 5: STRIDE analysis...

        ## Threat List
        | ID | Category | Description | Priority |
        | T-S-P001-001 | Spoofing | API lacks authentication | Critical |
        ...
```

**Quick Security Check**
```
User: Quick security check on this service @/path/to/service

Claude: Found 3 high-severity threats:
        - T-S-P001-001: API endpoint lacks authentication
        - T-E-P002-001: Delete endpoint missing authorization
        - T-I-DF001-001: Sensitive data transmitted in plaintext
```

**AI/LLM Applications**
```
User: Analyze security risks for this RAG app @/path/to/rag-app

Claude: [Enables OWASP LLM Top 10 extension]
        - LLM01: Prompt Injection risk
        - LLM06: Sensitive information disclosure risk
        ...
```

### Manual Script Execution

```bash
# Project structure analysis (Phase 1)
python scripts/list_files.py ./project --categorize --detect-type --pretty

# Knowledge base queries (Phase 5/6/7)
python scripts/unified_kb_query.py --full-chain CWE-89
python scripts/unified_kb_query.py --capec CAPEC-66 --attack-chain
python scripts/unified_kb_query.py --attack-technique T1059
python scripts/unified_kb_query.py --cwe CWE-89 --mitigations
python scripts/unified_kb_query.py --all-llm
```

---

## Core Capabilities

### 8-Phase Workflow Outputs

| Phase | Output |
|-------|--------|
| **1-4** | Project overview, DFD diagram, key interfaces/boundaries/data nodes, security design matrix |
| **5** | Threat list (STRIDE+CWE+ATT&CK+LLM) |
| **6** | **Validation methods** (attack paths + POC) |
| **7** | **Mitigations** (remediation suggestions per threat) |
| **8** | `THREAT-MODEL-REPORT.md` comprehensive report |

### Capability Matrix

| Capability | Description |
|------------|-------------|
| 8-Phase Serial Workflow | Strict sequential execution with phase output chaining |
| DFD Construction | Mermaid templates + element inventory + trust boundaries |
| STRIDE Matrix | TMT-compatible STRIDE per Interaction |
| Threat ID | Standard format `T-{STRIDE}-{Element}-{Seq}` |
| Dual Database KB | Core DB (969 CWE, 615 CAPEC) + CVE extension (323K+ CVE) |
| Attack Path Validation | CAPEC + ATT&CK attack chain mapping + POC design |
| KB-Enhanced Mitigations | Query knowledge base to generate customized mitigations per threat |

### Scenario Extensions

| Extension | Coverage |
|-----------|----------|
| **Cloud Services** | AWS / Azure / GCP / Alibaba Cloud / Tencent Cloud |
| **AI/LLM** | OWASP LLM Top 10 + AI component threats |
| **CVE Validation** | 323K+ CVE + KEV (Known Exploited Vulnerabilities) checks |

---

## Documentation

| Document | Content |
|----------|---------|
| **[SKILL.md](SKILL.md)** | Claude Code skill entry point (8-phase workflow overview) |
| **[WORKFLOW.md](WORKFLOW.md)** | Detailed 8-phase deep workflow templates |
| **[GUIDE.md](GUIDE.md)** | Design philosophy, script reference, KB architecture, troubleshooting |
| **[EXAMPLES.md](EXAMPLES.md)** | 5 real-world cases (REST API, microservices, AI/LLM, cloud-native) |

### Architecture Documentation

| Document | Content |
|----------|---------|
| **[references/KNOWLEDGE-ARCHITECTURE-v5.2.md](references/KNOWLEDGE-ARCHITECTURE-v5.2.md)** | Knowledge base architecture (Dual System A+B) |
| **[references/COMPREHENSIVE-ARCHITECTURE-WORKFLOW-GUIDE.md](references/COMPREHENSIVE-ARCHITECTURE-WORKFLOW-GUIDE.md)** | Complete architecture and workflow guide |

---

## Knowledge Architecture

### Dual Knowledge System

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Dual Knowledge Architecture                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  System A: Security Control Hierarchy        System B: Threat Intelligence  │
│  ─────────────────────────────────           ─────────────────────────────  │
│  L1: ASVS Control Requirements               L1: STRIDE Classification      │
│  L2: Security Implementation Patterns        L2: CWE+CAPEC+ATT&CK Mapping   │
│  L3: Verification Test Cases                 L3: CVE Vulnerability Database │
│                                              L4: KEV Real-time Intelligence │
│                                                                              │
│  Verification Set: WSTG(121) + MASTG(206) + ASVS(345) = 672 Tests          │
│  → Mapped to 1,269 STRIDE+Test combinations                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Threat Intelligence Chain

```
STRIDE → CWE → CAPEC → ATT&CK → CVE/KEV
  L1      ├────── L2 ──────┤    L3 + L4

L1 STRIDE → L2 Threat Intelligence:
───────────────────────────────────────────────────────────────────────────────
S(Spoofing)      → CWE-287/290/307 → CAPEC-151/194/600 → T1078/T1110 → CVE-*
T(Tampering)     → CWE-20/77/89    → CAPEC-66/88/248   → T1190/T1059 → CVE-*
R(Repudiation)   → CWE-117/223/778 → CAPEC-93/268      → T1070/T1562 → CVE-*
I(Info Disclosure)→ CWE-200/209/311 → CAPEC-116/157/497 → T1552/T1213 → CVE-*
D(Denial of Svc) → CWE-400/770/918 → CAPEC-125/227/469 → T1498/T1499 → CVE-*
E(Elev. of Priv) → CWE-269/284/862 → CAPEC-122/233/17  → T1068/T1548 → CVE-*
```

---

## LLM Compatibility

### Design Principles

This skill follows **LLM-Native Design** principles for broad compatibility:

| Principle | Description |
|-----------|-------------|
| **Context Not Control** | Knowledge base empowers LLM intelligence rather than constraining it |
| **LLM Autonomous** | KB provides context; LLM performs semantic reasoning |
| **Script as Blackbox** | Scripts handle deterministic operations; LLM handles analysis |
| **Dual-Track Knowledge** | Security Controls (defensive) + Threat Patterns (offensive) |

### Agent Architecture

Supports parallel sub-agent patterns for Phases 5/6/7:

```
Main Agent ──► Risk 1 ──► Sub-Agent 1 ──► KB Query ──► Result 1
           ──► Risk 2 ──► Sub-Agent 2 ──► KB Query ──► Result 2
           ──► Risk N ──► Sub-Agent N ──► KB Query ──► Result N
                                            │
           ◄─────────── Aggregate Results ──┘
```

**Scale Thresholds**:
| Project Scale | Files | Strategy |
|--------------|-------|----------|
| Small | <50 | Standard 8-phase |
| Medium | 50-200 | Module-priority analysis |
| Large | 200-500 | Subsystem split + merge |
| Very Large | >500 | Parallel sub-agents |

---

## Version History

### v2.2.1 (Current)

- **Phase 2 DFD/CFD Knowledge Enhancement**: Added 4 YAML pattern files for improved DFD/CFD analysis
  - `framework-routing-patterns.yaml`: Framework routing detection (Express, FastAPI, Spring, AI/LLM frameworks)
  - `data-store-patterns.yaml`: Data store identification patterns
  - `security-checkpoint-patterns.yaml`: Security checkpoint detection patterns
  - `completeness-rules.yaml`: Phase 2 output completeness validation rules
- **MCP Architecture & LLM Security Detection**: Enhanced detection for MCP Server patterns and Agent architecture threats
- **Claude Code Ecosystem Security Analysis**: Skills and plugin (MCP Server, hooks) security analysis integration
- **Session Version Control**: Workflow phase traceability and version management improvements
- **Test Coverage Improvement**: `unified_kb_query.py` coverage increased to 53% (target ≥80%)

### v2.1.3

- **STRIDE Name-to-Code Mapping Fix**: `get_cwes_for_stride_sqlite()` now accepts both full names ("spoofing") and codes ("S")
- **FTS5 Index Rebuild**: All 12 full-text search indexes rebuilt and verified
- **E2E Interface Tests**: Comprehensive 25-test suite for UnifiedKnowledgeBase
- **LLM Compatibility Documentation**: Added design principles and agent architecture sections
- **Semantic Embeddings**: 3,278 entries for intelligent threat lookup

### v2.1.2

- **ATT&CK Tactics Parsing Fix**: Changed `json.loads()` to `str.split(',')` for comma-separated fields
- **FTS Exception Handling**: Added `sqlite3.DatabaseError` catch for corrupted FTS indexes

### v2.1.1

- **ATT&CK JSON Parsing Fix**: Corrected tactics and platforms field parsing
- **Obsolete Test Script Removed**: Deleted reference to non-existent database

### v2.1.0

- **Directory Structure Refactoring**: Reorganized to `references/`, `assets/knowledge/`, `assets/schemas/`, `assets/templates/`

### v2.0.0

- **STRIDE→Test Mapping Expansion**: 162 → 1,269 test mappings
- **Verification Set Integration**: WSTG(121) + MASTG(206) + ASVS(345)
- **Dual Knowledge Architecture**: System A (Controls) + System B (Threats)
- **Bilingual Documentation**: Full English + Chinese documentation

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

---

**Version 2.2.1** | [Full Documentation](GUIDE.md) | [Changelog](CHANGELOG.md) | [中文版](README-cn.md)
