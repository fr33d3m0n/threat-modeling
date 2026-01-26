# Changelog

All notable changes to the STRIDE Threat Modeling Skill are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1] - 2026-01-27

### Added

#### 1. DFD/CFD Analysis Phase 2 Enhancement (Phase 2 分析强化)

**Knowledge Base v1.1 Implementation** (`assets/knowledge/phase2/`)
- **framework-routing-patterns.yaml v1.1**: Added 10 AI/LLM frameworks
  - MCP, LangChain, LlamaIndex, CrewAI, AutoGen, Semantic Kernel
  - Claude Agent SDK, OpenAI Agents, Vercel AI, Dify
- **security-checkpoint-patterns.yaml v1.1**: Added 6 AI/LLM security checkpoints
  - prompt_safety, output_validation, tool_function_control
  - rag_security, agent_governance, resource_control
- **data-store-patterns.yaml v1.1**: Added `stride_relevance` field for Phase 5 mapping
- **completeness-rules.yaml v1.1**: Added `data_flow_tracing_hints` for enhanced analysis

**WORKFLOW.md Phase 2 Integration**
- Added 5 sub-phase structure (2.1-2.5) for systematic DFD analysis
- Added knowledge file loading instructions with conditional loading
- Enhanced checkpoint with AI/LLM framework detection requirements

#### 2. MCP & LLM/Agent Knowledge Base and Detection (AI/LLM 安全检测)

**Phase 1 MCP Detection Enhancement** (ENH-001)
- Added MCP/AI Agent config file detection to Step 4
- Added MCP Server configuration table to output template
- Added Tool/Function definition table and Agent configuration checklist
- Added LLM integration table and MCP security preliminary assessment

**Phase 4 AI/LLM Security Domain** (Domain 10)
- Added 6 security checkpoints with OWASP LLM Top 10 mapping
- Integrated into WORKFLOW.md Phase 4 security design review

**VALIDATION.md v2.1.0 AI/LLM Risk Validation Guide** (ENH-002)
- Added AI/LLM threat classification table (OWASP LLM Top 10)
- Added MCP Server risk validation checklist (YAML format)
- Added Prompt Injection POC template and Agent Tool Abuse POC template
- Added AI/LLM Attack Path template (ASCII art)
- Updated Phase 6 checkpoint with AI/LLM validation items

**Research Documents Created**
- `research/SKILL-AGENT-DETECTION-ENHANCEMENT-DESIGN.md` (49KB)
  - Hybrid detection architecture: Script 72% + Claude 28%
  - 21 attack type classification with supply chain scanner design
- `research/SKILL-AGENT-MALICIOUS-ATTACK-RESEARCH.md` (43KB)
  - Comprehensive malicious attack classification
  - Claude Code ecosystem attack vector analysis

#### 3. Claude Code Ecosystem Detection (Agent/Skill/Command 检测)

**Phase 1 Claude Code Detection** (ENH-001a)
- Config files: CLAUDE.md, .claude/settings.json, .claude.toml
- Hooks: .claude/hooks/ directory monitoring
- Skills: .claude/skills/*/SKILL.md, skill.json detection
- Commands: .claude/commands/*.md, COMMANDS.md
- Contexts: .claude/contexts/*.md
- Agents: .claude/agents/*.md
- Rules: .claude/rules/*.md
- MCP Servers: .claude/mcp_servers.json
- Permissions: .claude/settings.local.json

**Cross-Phase Claude Code Integration** (ENH-004)
- Phase 2 Checkpoint: MCP/Claude Code DFD inclusion requirements
- Phase 3 Checkpoint: MCP/Claude Code trust boundary items
- Phase 4 Checkpoint: Claude Code security evaluation items
- Phase 5 Checkpoint: Claude Code threat generation requirements
- Final Checkpoint: Cross-Phase Consistency Verification table

**REPORT.md Claude Code Templates** (ENH-003)
- Added Claude Code Ecosystem Mitigation Template (YAML)
- Added Claude Code report chapter template (§11)
- Added Claude Code content mapping to Step 8.2

#### 4. Session Version Control (任务过程文件多版本保留)

**Session Management Architecture** (ENH-005, ENH-006)
- Implemented single-file `_session.yaml` architecture (~20 fields)
- Session ID format: `{PROJECT_NAME}-{YYYYMMDD}-{HHMMSS}`
- Multi-version storage: `.phase_working/{SESSION_ID}/` subdirectories
- Filesystem metadata (mtime/ctime) replaces explicit timestamps
- Deprecated original 3-file design (~80 fields) - YAGNI/KISS principle

**Files Updated**
- WORKFLOW.md v2.3.0: Session Management section
- SKILL.md: Simplified directory structure
- VALIDATION.md: Path updates with {SESSION_ID}
- REPORT.md: Path updates with {SESSION_ID}
- report-naming.schema.md v1.6.0

#### 5. Test Coverage Enhancement (测试覆盖率提升)

**New Test Files Created** (`tmp_check/`)

| Test File | Tests | Coverage Area |
|-----------|-------|---------------|
| `test_cp3_validation.py` | 16 | CP3 Report Count Validation (ARCH-002) |
| `test_unified_kb_coverage.py` | 44 | unified_kb_query.py method coverage |
| `test_8phase_integration.py` | 41 | 8-Phase workflow integration |
| `conftest.py` | - | Session-scoped kb fixture (TEST-001 fix) |

**Issues Fixed**
- TEST-001: Created conftest.py with kb fixture (10 test errors resolved)
- ARCH-001: Added ElementID validation to stride_matrix.py
- ARCH-003: Fixed argparse in validate_count_conservation.py

### Changed

**Version Bumps**
- VERSION: 2.1.3 → 2.2.1
- SKILL.md skill_version: 2.2.1
- WORKFLOW.md: v2.3.0
- VALIDATION.md: v2.1.0
- report-naming.schema.md: v1.6.0

**Element ID Format Unification**
- Before: `P01`, `DS01`, `DF01` (zero-padded)
- After: `P1`, `DS1`, `DF1` (no leading zeros)
- Rationale: Consistency with Threat ID format (T-S-P1-001)

### Statistics

| Metric | v2.1.3 | v2.2.1 |
|--------|--------|--------|
| Total Tests | 126 | 227 |
| New Tests Added | - | 101 |
| Test Pass Rate | 100% | 100% |
| Knowledge Files | 12 | 16 |
| AI/LLM Frameworks | 0 | 10 |
| AI/LLM Checkpoints | 0 | 6 |
| unified_kb Coverage | baseline | 53% |

---

## [2.1.3] - 2026-01-19

### Added

1. **LLM Compatibility Documentation** (README.md, README-cn.md)
   - Added "LLM Compatibility" section with design principles (Context Not Control, LLM Autonomous, Script as Blackbox, Dual-Track Knowledge)
   - Added "Agent Architecture" section with parallel sub-agent pattern diagram
   - Added scale thresholds table (Small/Medium/Large/Very Large projects)

2. **E2E Interface Test Suite** (`tmp_check/test_unified_kb_interfaces.py`)
   - Comprehensive 25-test suite for UnifiedKnowledgeBase
   - Tests all major public interfaces: core data access, STRIDE integration, FTS search, chain queries, YAML layer, cloud/LLM, verification testing, statistics

### Fixed

3. **STRIDE Name-to-Code Mapping** (`unified_kb_query.py:979-1013`)
   - `get_cwes_for_stride_sqlite()` now accepts both full names ("spoofing", "tampering") and single-letter codes ("S", "T")
   - Added `stride_name_to_code` mapping dictionary
   - Normalizes input to handle spaces and case variations
   - Before fix: "spoofing" returned 0 items; After: returns 48 CWEs

4. **FTS5 Index Rebuild** (`tmp_script/rebuild_fts_indexes.py`)
   - All 12 FTS5 indexes rebuilt and verified
   - Fixed column mappings for `stride_category_fts`, `wstg_test_fts`, `mastg_test_fts`
   - Verified search functionality with test queries

### Changed

5. **Version Bump**
   - VERSION: 2.1.2 → 2.1.3
   - SKILL.md header: Version 2.1.0 → 2.1.3
   - marketplace.json: version 2.1.2 → 2.1.3
   - README.md/README-cn.md: Version 2.0 → 2.1.3

### Statistics

| Metric | v2.1.2 | v2.1.3 |
|--------|--------|--------|
| Interface Tests | 0 | 25 |
| STRIDE-CWE Query | Code only | Name + Code |
| FTS Indexes | Corrupted | Rebuilt (12/12) |
| Semantic Embeddings | 3,278 | 3,278 (verified) |

---

## [2.1.2] - 2026-01-15

### Fixed

1. **ATT&CK Tactics Parsing** (`unified_kb_query.py:1027-1028`)
   - Changed `json.loads()` to `str.split(',')` for comma-separated text fields
   - Affects: `tactics` and `platforms` fields in `get_attack_technique()`

2. **FTS DatabaseError Exception Handling** (`unified_kb_query.py`)
   - Added `sqlite3.DatabaseError` catch for corrupted FTS indexes
   - Graceful fallback when FTS tables are unavailable

---

## [2.1.1] - 2026-01-03

### Fixed

1. **ATT&CK JSON Parsing** (`unified_kb_query.py:1027-1028`)
   - Changed `json.loads()` to `str.split(',')` for comma-separated text fields
   - Affects: `tactics` and `platforms` fields in `get_attack_technique()`

### Removed

2. **Obsolete Test Script** (`tmp_check/verify_kb_v2.py`)
   - Deleted script that referenced non-existent `security_kb_v2.sqlite`

### Changed

3. **Documentation Update** (`GUIDE.md`, `GUIDE-cn.md`, `assets/knowledge/README.md`)
   - Removed references to non-existent `diagram-templates/` directory
   - DFD templates are now in `assets/templates/DFD-TEMPLATES.md`

---

## [2.1.0] - 2026-01-03 ✅ RELEASED

### Changed

#### Directory Structure Refactoring (目录结构重构)
- **BREAKING**: Restructured skill directory layout for better organization
  - `docs/` → `references/` (design documents, architecture guides)
  - `knowledge/` → `assets/knowledge/` (SQLite databases, YAML mappings, control sets)
  - `schemas/` → `assets/schemas/` (data format definitions)
  - `templates/` → `assets/templates/` (report templates)
  - `scripts/` remains unchanged

#### New Directory Structure
```
threat-modeling/
├── scripts/           # Python scripts (unchanged)
├── references/        # Design documents (was docs/)
├── assets/
│   ├── knowledge/     # SQLite + YAML knowledge base
│   ├── schemas/       # Data format definitions
│   └── templates/     # Report templates (9 files)
└── [workflow files]   # SKILL.md, WORKFLOW.md, etc.
```

### Updated
- **Python Scripts**: Updated 7 scripts with new `assets/knowledge/` path
  - `unified_kb_query.py`, `build_knowledge_base.py`, `prebuild_semantic_index.py`
  - `build_cve_index.py`, `kb_incremental_update.py`, `expand_capec_attack_mappings.py`
  - `query_kb.py` (path + import statement)
- **MD Documents**: Updated all path references in core workflow files
  - SKILL.md, REPORT.md, GUIDE.md, GUIDE-cn.md, README.md, README-cn.md
  - EXAMPLES.md, EXAMPLES-cn.md, CHANGELOG.md
  - All files in `references/` and `assets/schemas/`
- **Progress Document**: Updated `.claude/progress.md` with new paths

### Migration Notes
- No functional changes to the threat modeling workflow
- All KB queries, STRIDE analysis, and report generation work unchanged
- If you have custom scripts referencing old paths, update:
  - `knowledge/` → `assets/knowledge/`
  - `templates/` → `assets/templates/`
  - `schemas/` → `assets/schemas/`
  - `docs/` → `references/`

---

## [2.0.7] - 2026-01-02

### Added

#### Executive Summary Critical Risks Section
- **Section 1.3 Critical 风险清单**: New section listing ALL Critical-level risks
  - Replaces conceptual "Top 5" approach with complete Critical risk enumeration
  - Table includes: 序号, 风险ID, 风险名称, STRIDE, 元素, CWE, CVSS, 修复状态
  - Placeholder: `{ALL_CRITICAL_RISKS_TABLE}`

#### Phase Document Reference Hints
- **Chapter 3 (STRIDE威胁分析)**: Added section 3.9 详细文档参考
  - Links to `P5-STRIDE-THREATS.md` for complete threat enumeration and CWE/CAPEC mapping
- **Chapter 4 (安全功能设计评估)**: Added section 4.3 详细文档参考
  - Links to `P2-DFD-ANALYSIS.md`, `P3-TRUST-BOUNDARY.md`, `P4-SECURITY-DESIGN-REVIEW.md`
- **Chapter 5 (风险验证与POC设计)**: Added section 5.4 详细文档参考
  - Links to `P6-RISK-VALIDATION.md` for POC code and attack path analysis

### Changed

#### Report Chapter Reordering
- **Chapter 3**: Now STRIDE威胁分析 (Threat Summary) — was Chapter 4
- **Chapter 4**: Now 安全功能设计评估 (Security Control Assessment) — was Chapter 3
- **Rationale**: Threat analysis (P5) logically follows architecture overview (Chapter 2)

#### Section Renumbering
- Executive Summary sections renumbered: 1.3 → Critical风险清单, 1.4 → 关键发现, 1.5 → 立即行动建议
- Chapter 3 subsections: 3.1-3.9 (threat tables + reference)
- Chapter 4 subsections: 4.1-4.3 (security domains + reference)
- Chapter 5 subsections: 5.1-5.4 (POC verification + reference)

---

## [2.0.6] - 2026-01-02

### Added

#### Fix Location Tracking for Mitigations (修复定位)
- **Problem**: Mitigation measures lacked precise fix location info (module, function, file, line)
- **Solution**: Enhanced mitigation template and workflow with comprehensive fix location tracking

- **MITIGATION-MEASURES.template.md v2.0**: Enhanced mitigation block template
  - Added 🎯 修复定位 section with:
    - 主要修复位置 table (module, function, file, line range)
    - 修复点详情 code block with context lines
    - 关联修复位置 table for coordinated changes
  - Change types: add, modify, delete, config

- **REPORT.md Phase 7**: Enhanced mitigation workflow
  - Added Step 6: Collect fix location information
  - Added `fix_location` structure to mitigation output template
  - Updated checkpoint with fix location verification items

#### New Schema
- **assets/schemas/mitigation-detail.schema.md v1.0.0**: Formal schema for mitigation structure
  - Core entity definition with traceability
  - `fix_location.primary`: module, function, file, line_range
  - `fix_location.context`: before, vulnerable, after lines
  - `fix_location.related`: coordinated change locations
  - Validation rules with Python example

### Changed
- Phase 7 steps renumbered (old steps 6-7 → new steps 7-8)
- Mitigation template version updated to v2.0

---

## [2.0.5] - 2026-01-02

### Added

#### Project Scale Metrics Enhancement
- **Problem**: Report section 1.1 项目概述 lacked quantitative project metrics (LOC, file counts, language distribution)
- **Solution**: Enhanced Phase 1 workflow and report templates with comprehensive code statistics

- **RISK-ASSESSMENT-REPORT.template.md**: Enhanced section 1.1 项目概述
  - Added 基本信息 table (project name, type, tech stack, scope, repo)
  - Added 项目规模指标 table (LOC, files, dirs, modules, dependencies)
  - Added 语言分布 table (language, file count, LOC, percentage)
  - Added 安全相关模块 table (module path, function, files, security level)

- **WORKFLOW.md Phase 1**: Enhanced project understanding workflow
  - Added Step 3: Collect project scale metrics (cloc/tokei/manual methods)
  - Added 项目规模指标 section to Required Output Template
  - Added checkpoint item for scale metrics verification

#### New Tooling
- **scripts/collect_code_stats.py**: Automated code statistics collection
  - Collects LOC, file counts, directory counts, module counts
  - Detects language distribution with percentage breakdown
  - Identifies security-related modules (auth, crypto, data access, API, config, validation)
  - Supports multiple output formats: json, markdown, yaml
  - Integrates with cloc/tokei when available

### Changed
- Phase 1 steps renumbered (old steps 3-4 → new steps 4-5)
- Report template now includes comprehensive project quantification

---

## [2.0.4] - 2026-01-02

### Added

#### Data Architecture Redesign — CRITICAL FIX
- **Problem**: 79% content loss from P5 (120 threats) to final reports (25 risks)
- **Root Causes Identified**:
  1. Missing entity relationships between Threat and ValidatedRisk
  2. ID format inconsistency (T-xxx vs RISK-xxx vs VR-xxx)
  3. No traceability mechanism from VR back to original threats
  4. No count conservation validation

- **Solution: Core Entity Model**:
  ```
  Finding (P1-P4)  →  Threat (P5)  →  ValidatedRisk (P6)  →  Mitigation (P7)
    F-P{N}-{Seq}     T-{S}-{E}-{Seq}     VR-{Seq}             M-{Seq}
  ```

- **Key Design Decisions**:
  - `threat_refs[]` is now **MANDATORY** in every ValidatedRisk
  - `threat_disposition` table tracks every P5 threat's processing result
  - Count conservation formula: `P5.total = consolidated_into_vr + excluded_with_reason`
  - Forbidden ID formats: `RISK-xxx` (use `VR-xxx`), `T-E-RCE-001` (keep ElementID)

#### Files Updated
- **SKILL.md**: Added "Core Data Model" section with entity definitions, relationships, ID conventions
- **WORKFLOW.md**: Added "P5 Output Structure" with `threat_inventory`, `element_threat_map`
- **VALIDATION.md**: Added Step 6.5.1 "Threat Disposition Tracking", updated Step 6.6 completeness
- **REPORT.md**: Added "Traceability Preservation Rules", Step 8.4 count conservation

#### Template Updates
- **assets/templates/RISK-INVENTORY.template.md**: Added `Threat Refs` column, count conservation section
- Risk detail templates now use `VR-{Seq}` ID format with mandatory `threat_refs` field

#### Schema Updates (v2.0)
- **assets/schemas/risk-detail.schema.md**: Added ValidatedRisk entity, `threat_refs[]` required field
- **assets/schemas/phase-risk-summary.schema.md**: Added `threat_disposition` structure for P6
- **assets/schemas/report-naming.schema.md**: Updated to v1.5.0

#### New Tooling
- **scripts/validate_count_conservation.py**: Validates P5→P6 count conservation, VR threat_refs completeness

### Changed
- Report tables now require `Threat Refs` column for traceability
- ValidatedRisk entries must include `threat_refs[]` array (cannot be empty)

---

## [2.0.2] - 2025-12-31

### Added

#### Report Output Enforcement — CRITICAL FIX
- **Problem**: Reports generated with wrong name (`THREAT-MODEL-REPORT.md`) in wrong location (project root)
- **Expected**: `Risk_Assessment_Report/{PROJECT}-RISK-ASSESSMENT-REPORT.md` + 4 required reports + 6 phase docs
- **Root Cause**: SKILL.md YAML `description` and CLAUDE.md lacked output directory requirements
- **Fix**: Added output requirements to both highest-priority locations:
  - CLAUDE.md: Added "Phase 8 报告输出规范" section with directory structure
  - SKILL.md description: Added "MANDATORY OUTPUT" block with forbidden patterns
- **Enforcement**:
  - Directory: `{PROJECT_ROOT}/Risk_Assessment_Report/`
  - Main report: `{PROJECT}-RISK-ASSESSMENT-REPORT.md` (PROJECT=UPPERCASE)
  - Required: 4 reports + 6 phase docs (P1-P6)
  - ❌ FORBIDDEN: `THREAT-MODEL-REPORT.md` or reports in project root

#### Phase Todo Creation — TRUE ROOT CAUSE FIX
- **True Root Cause**: CLAUDE.md (project instructions) defined **7 phases**, while SKILL.md defined **8 phases**
- **Priority Conflict**: Claude Code reads `CLAUDE.md > SKILL.md`, so LLM followed 7-phase definition
- **Fix**: Updated CLAUDE.md to use correct 8-phase workflow matching SKILL.md
- **Changes to CLAUDE.md**:
  - Updated "核心目标" table: 7 phases → 8 phases
  - Updated "按阶段的执行者分配" table: 7 phases → 8 phases
  - Updated ASCII workflow diagram: 7 phases → 8 phases
  - Updated "LLM vs Script 职责边界": 7 phases → 8 phases
  - Added explicit warnings: "Phase 6: 风险验证 ← NOT MITIGATION!"
  - Added TodoWrite enforcement note

### Changed

#### Database Architecture Cleanup
- Removed `unified-kb.sqlite` (empty file, unused)
- Removed `security_kb_v2.sqlite` (legacy, superseded by security_kb.sqlite)
- Updated `unified_kb_query.py` to remove legacy V2 fallback code
- Final architecture: `security_kb.sqlite` (core) + `security_kb_extension.sqlite` (CVE)

#### Template Directory Reorganization
- Moved `knowledge/diagram-assets/templates/dfd-templates.md` → `assets/templates/DFD-TEMPLATES.md`
- Removed empty `diagram-assets/templates/` directory
- Templates directory now contains all template files

#### Report Quality Enhancement — Phase 6 Depth Fix
- **Problem**: New reports extremely simplistic compared to old `THREAT-MODEL-REPORT.md`
- **Expected**: Chapters 4 (风险验证与POC设计) and 5 (攻击路径分析) should match old report quality
- **Root Cause**: WORKFLOW.md, SKILL.md, and report template missing POC and attack chain templates
- **Fixes Applied**:

**1. WORKFLOW.md Phase 6 Templates** (4 new templates added):
- POC Verification Methodology Template (验证方法论表)
- POC Code Example Template (独立POC代码块模板)
- Attack Path Feasibility Matrix Template (攻击路径可行性矩阵)
- Attack Chain ASCII Art Box Template (攻击链ASCII图框模板)

**2. RISK-ASSESSMENT-REPORT.template.md** (restructured from 7 to 9 sections):
- NEW Section 5: 风险验证与POC设计 — POC verification methodology, status, code examples
- NEW Section 6: 攻击路径分析 — attack chain diagrams, feasibility matrix, heatmap
- Renumbered: Section 5→7, Section 6→8, Section 7→9

**3. SKILL.md Phase 6 Output Structure** (enhanced from 4 to 5 parts):
- Part 1: risk_summary — added verification coverage statistics
- Part 2: poc_details — NEW complete POC block structure with code
- Part 3: risk_details — added related_poc linkage
- Part 4: attack_path_matrix — NEW feasibility scoring matrix
- Part 5: attack_chains — NEW with ASCII diagram field

**4. SKILL.md Phase 8 Report Structure** (updated to match 9-section template)

### Planned Improvements
- [ ] P3-1: Add EXAMPLES.md practical examples
- [ ] P3-2: Optimize semantic search index building
- [ ] P3-3: Add KB incremental update mechanism
- [ ] Expand CAPEC→ATT&CK mappings (currently 36)

---

## [2.0.1] - 2025-12-31

### Added

#### Language Adaptation Rules (语言自适应规则)
- **Context-based language detection**: Output language follows user instruction language
- **Affected elements**: File names, directory names, report content
- **Override mechanism**: `--lang=xx` flag (en, zh, ja, ko, es, fr, de, pt, ru)
- **Implementation**: Single English template + LLM real-time translation
- **Technical terms preserved**: STRIDE, DFD, CWE, CAPEC, ATT&CK remain in English
- Added file name mapping table (English/Chinese/French/Spanish)

#### Penetration Test Plan as Required Report
- **PENETRATION-TEST-PLAN.md** upgraded from conditional to **required** report
- Now generates for all threat modeling sessions, not just P0/P1 threats
- Updated SKILL.md, WORKFLOW.md, and report-naming.schema.md accordingly

#### ATT&CK Integration in Penetration Test Template
- Added **Appendix E: MITRE ATT&CK 技术映射** to PENETRATION-TEST-PLAN.template.md
  - E.1: STRIDE → ATT&CK mapping reference table
  - E.2: Project ATT&CK techniques list
  - E.3: ATT&CK attack chain analysis diagram
  - E.4: Detection and response recommendations
- Enhanced test targets table with ATT&CK column
- Added ATT&CK ID and Tactic fields to vulnerability info table

#### Workflow Steps 8.7 and 8.8
- **Step 8.7**: Penetration Test Plan Generation (渗透测试方案生成) - Required
- **Step 8.8**: Phase Output Publication (阶段产物发布) - Required
- Updated Three-Layer Report Architecture in WORKFLOW.md

### Changed

#### Phase Output File Naming
- Phase output files now **keep English names** when copied to Risk_Assessment_Report/
- Pattern: `P{N}-{PHASE-NAME}.md` (e.g., P1-PROJECT-UNDERSTANDING.md)
- Changed from originally planned Chinese names (P1-项目理解.md)

#### Report Naming Schema v1.4.0
- Reorganized report type matrix with 4 required reports
- Updated section 4.4 with phase output file examples
- Added PENETRATION-TEST-PLAN to validation regex

### Statistics

| Metric | v2.0.0 | v2.0.1 |
|--------|--------|--------|
| Required Reports | 3 | 4 |
| Workflow Steps | 8.6 | 8.8 |
| Template Appendices | D | E |

---

## [2.0.0] - 2025-12-30

### Major Version Release

Complete redesign of STRIDE Deep Threat Modeling with enhanced workflow and report architecture.

### Added

#### Three-Layer Report Architecture
- **Layer 1**: WORKFLOW.md - Execution logic and step definitions
- **Layer 2**: assets/templates/*.template.md - Report templates with placeholders
- **Layer 3**: assets/schemas/*.schema.md - Validation rules and naming conventions

#### Report Templates System
- RISK-ASSESSMENT-REPORT.template.md
- RISK-INVENTORY.template.md
- MITIGATION-MEASURES.template.md
- PENETRATION-TEST-PLAN.template.md

#### Report Naming Schema
- Standardized naming convention: `{PROJECT}-{REPORT-TYPE}.md`
- Validation rules for all report types
- Version tracking and compliance requirements

---

## [1.0.4] - 2025-12-26

### Added

#### CVE Query Enhancement
- **`--cve-limit N`**: New CLI parameter to control CVE result count
  - Works with `--cve-search` and `--cve-for-cwe`
  - Default: 10, Maximum: 100
  - Example: `--cve-for-cwe CWE-89 --cve-limit 5`

### Changed

#### Documentation Updates
- Updated SKILL.md with `--cve-limit` parameter documentation
- Completed comprehensive workflow-KB mapping analysis
- Verified 39+ CLI arguments coverage

### Verified

#### Complete Testing (Phase 3)
- All 6 scripts tested and verified functional
- 45 test cases executed, 98% pass rate
- KB query performance validated (<200ms average)
- Semantic search confirmed working (2-3s initial, <300ms cached)

### Statistics

| Metric | v1.0.2 | v1.0.4 |
|--------|--------|--------|
| unified_kb_query.py Lines | ~2920 | ~2925 |
| CLI Arguments | 39+ | 40+ |
| Test Coverage | - | 95% |

---

## [1.0.2] - 2025-12-26

### Added

#### OWASP Web Top 10 Query Interface (P2-1)
- **`--owasp A01`**: Query single OWASP category with associated CWEs
- **`--all-owasp`**: Get all 10 OWASP Web Top 10 categories overview

#### STRIDE → Compliance Query Interface (P2-3)
- **`--stride-compliance S|T|R|I|D|E`**: Query compliance controls for STRIDE category
- **`--all-stride-compliance`**: Get compliance controls for all 6 STRIDE categories (51 total)

### Verified
- **P1-1**: WSTG (121), MASTG (206), ASVS (345) records confirmed complete
- **P1-2**: OWASP→CWE mappings (248 records) confirmed
- **P2-2**: Cloud→CWE mappings (27 entries) confirmed

### Fixed
- `_get_connection()` → `_get_sqlite_connection()` method name error
- `c.cwe_id` → `c.id` column name in JOIN query

---

## [1.0.1] - 2025-12-25 15:50:02

### Added

#### Report Output Enhancements (WORKFLOW.md)
- **I2+I4: 组件拓扑 ASCII Art** - 系统架构可视化图
- **I2: 数据流图 (DFD) 增强** - ASCII art 正文展示 + Mermaid 附件
- **I3+I5: 威胁详细分析模板** - T-{STRIDE}-{NN} 详细分析块
  - 攻击向量、代码定位、详细说明
  - 原因分析、验证方法/POC、缓解措施
- **I6: 攻击面热力图** - 组件威胁数量可视化
- **Appendix B: Mermaid DFD 源码** - 可渲染的 DFD 图

#### Security Controls 集成 (SKILL.md)
- **I7: Phase 4 Security Controls 映射** - 安全域 → KB 文件对照表
  - 10 个安全域的详细检查点映射
  - 按需查询模式，非强制依赖

### Changed

#### Phase 内聚性重构 (SKILL.md) - I8
- **所有阶段统一结构**:
  1. 核心分析目标 (Core Analysis Goal) - 明确目标，不依赖 KB
  2. 输入上下文 (Input Context) - 从前阶段接收的数据
  3. LLM 分析规划 (LLM Analysis Planning) - LLM 先规划分析路径
  4. KB 知识支持 (按需查询) - 仅在需要时查询，非强制
  5. 深度分析执行 (Deep Analysis Execution) - 结合 LLM + KB
  6. 输出上下文 (Output Context) - 传递给下阶段

- **I1: 执行摘要简化** - 移除"基于 STRIDE per Interaction 方法论"字样

### Statistics

| Metric | v1.0.0 | v1.0.1 |
|--------|--------|--------|
| SKILL.md Lines | 811 | 1005 |
| WORKFLOW.md Lines | ~1200 | 1448 |

---

## [1.0.0] - 2025-12-25

### First Official Release

Code-first automated deep threat modeling toolkit with comprehensive security chain analysis.

### Features

#### 8-Phase Workflow
- **Phase 1**: Project Understanding - code structure analysis, dependency extraction
- **Phase 2**: Call Flow & DFD - data flow diagram construction
- **Phase 3**: Trust Boundaries - security boundary identification
- **Phase 4**: Security Design Assessment - security function evaluation
- **Phase 5**: STRIDE Analysis - threat enumeration with CWE/CAPEC/ATT&CK mapping
- **Phase 6**: Risk Validation - attack path verification, POC design
- **Phase 7**: Mitigation - KB-enriched remediation strategies
- **Phase 8**: Report Generation - comprehensive threat model report

#### Knowledge Base Integration
- **unified_kb_query.py**: 35-parameter query interface
- **security_kb.sqlite**: V2 schema with 974 CWE, 615 CAPEC, 835 ATT&CK techniques
- **CVE Integration**: 323,830 vulnerabilities with CWE mapping
- **KEV Integration**: 1,483 known exploited vulnerabilities (CISA)
- **OWASP 2025**: Latest Top 10 mappings
- **LLM Threats**: OWASP LLM Top 10 support

#### Core Improvements
- **Phase Context Protocol**: Cross-phase data flow mechanism
- **KB Query Decision Matrix**: Threat type → query sequence mapping
- **Large Project Handling**: Scale thresholds and subsystem analysis
- **KB Output Interpretation**: JSON field → phase usage guide
- **Element ID Naming Convention**: Standardized DFD element IDs
- **Scenario Identification**: Project type confirmation table

#### Path Compatibility
- **skill_path.sh**: Auto-detect skill installation path
- **kb wrapper**: Universal invocation from any directory

### Statistics

| Metric | Value |
|--------|-------|
| SKILL.md Lines | 811 |
| CWE Definitions | 974 |
| CAPEC Patterns | 615 |
| ATT&CK Techniques | 835 |
| CVE Entries | 323,830 |
| KEV Entries | 1,483 |

---

[Unreleased]: https://github.com/user/stride-threat-modeling/compare/v2.2.1...HEAD
[2.2.1]: https://github.com/user/stride-threat-modeling/compare/v2.1.3...v2.2.1
[2.1.3]: https://github.com/user/stride-threat-modeling/compare/v2.0.2...v2.1.3
[2.0.2]: https://github.com/user/stride-threat-modeling/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/user/stride-threat-modeling/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/user/stride-threat-modeling/compare/v1.0.4...v2.0.0
[1.0.4]: https://github.com/user/stride-threat-modeling/compare/v1.0.2...v1.0.4
[1.0.2]: https://github.com/user/stride-threat-modeling/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/user/stride-threat-modeling/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/user/stride-threat-modeling/releases/tag/v1.0.0
