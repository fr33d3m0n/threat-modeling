<!-- Threat Modeling Skill | Version 3.0.2 (20260204a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Changelog

All notable changes to the Threat Modeling Skill will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.2] - 2026-02-04

### Localization & Usability
- **English Localization**: All phase instructions (P1-P8) translated to English for better LLM compatibility
- **Extended Trigger Words**: Added security analysis, security audit, security check (EN/CN)
- **Removed**: compliance/合规检查 (out of core scope)

### Bug Fixes
- Fixed residual Chinese in P4 (L116-117, L145) and P5 (L126-128)

## [3.0.1] - 2026-02-03

### Architecture Optimization
- **File Responsibility Separation**: SKILL.md (WHAT & WHY) vs WORKFLOW.md (HOW & WHEN)
- **FSM Formalization**: 8-phase state machine with formal verification properties (Safety S1-S4, Liveness L1-L2)
- **4-Gate Sub-FSM**: Per-phase execution protocol (ENTRY → THINKING → PLANNING → EXECUTING → REFLECTING → EXIT)
- **Token Optimization**: 26.4% reduction (12,000 → 8,832 tokens) through de-duplication and cross-references
- **Cross-Reference Convention**: "See SKILL.md §X" pattern to maintain single source of truth

### Technical Changes
- Added `docs/SKILL-ARCHITECTURE-DESIGN.md` with FSM specification (§0, §0.1, §0.2)
- Simplified SKILL.md §10, §11 to constraint declarations
- Added WORKFLOW.md §1 Workflow State Machine definition
- Simplified WORKFLOW.md §3 data contracts (summary table instead of full schemas)
- Added `MEMORY.md` for project memory across sessions

## [3.0.0] - 2026-01-31

### Core Improvements
- **Context Efficiency**: Restructured for improved context completeness and execution efficiency
- **Systematic Analysis**: Enhanced attack path analysis with better coverage
- **Session History**: Multi-session version tracking for incremental analysis
- **CI/CD Integration**: Structured YAML phase output for external tool integration

### Technical Changes
- Separate phase instruction files (8 files, on-demand loading)
- Dual output model: YAML data (machine) + Markdown reports (human)
- PostToolUse hooks for automatic validation
- Extended security domains: AI/LLM, Mobile, Cloud, Agentic
- Chinese documentation (README-cn.md)

## [2.2.2] - 2026-01-29

### Added
- Session management with unique session IDs
- Data protocols for phase handoff
- Complete discovery validation

### Changed
- Improved validation integration
- Enhanced YAML block extraction

## [2.2.0] - 2026-01-28

### Added
- Phase output YAML blocks
- Validation integration framework

## [2.1.3] - 2026-01-20

### Added
- Phase 2 knowledge enhancement
- DFD methodology research

## [2.0.0] - 2025-12-30

### Added
- 8-phase workflow structure
- Knowledge base with CWE/CAPEC/ATT&CK
- Security control domains (10 core)

## [1.0.6] - 2025-12-30

### Added
- Initial release
- Basic STRIDE analysis capability
- Core knowledge base
