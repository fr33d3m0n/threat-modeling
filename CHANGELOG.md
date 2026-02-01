<!-- Threat Modeling Skill | Version 3.0.0 (20260201a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Changelog

All notable changes to the Threat Modeling Skill will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
