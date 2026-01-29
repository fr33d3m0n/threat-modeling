# STRIDE Threat Modeling Skill v3.0.0

Code-first automated threat modeling with 8-phase sequential workflow.

## Architecture Overview

V3.0 implements a **5-pillar architecture** designed for:
- **Progressive disclosure**: Load content on-demand, not upfront
- **Reduced cognitive load**: ~5K tokens per context tier vs 30K monolithic
- **Deterministic enforcement**: PostToolUse hooks for automatic validation
- **Clear separation of concerns**: Global rules, workflow contracts, phase instructions

## Directory Structure

```
threat-modeling-v3/
├── SKILL.md              (308 lines, ~5K tokens) - Global constraints only
├── WORKFLOW.md           (278 lines, ~3K tokens) - Orchestration contracts
├── phases/                                       - Phase-specific instructions
│   ├── P1-PROJECT-UNDERSTANDING.md   (337 lines)
│   ├── P2-DFD-ANALYSIS.md            (315 lines)
│   ├── P3-TRUST-BOUNDARY.md          (264 lines)
│   ├── P4-SECURITY-DESIGN-REVIEW.md  (273 lines)
│   ├── P5-STRIDE-ANALYSIS.md         (320 lines)
│   ├── P6-RISK-VALIDATION.md         (398 lines)
│   ├── P7-MITIGATION-PLANNING.md     (346 lines)
│   └── P8-REPORT-GENERATION.md       (422 lines)
├── contracts/
│   └── data-model.yaml               - Entity schemas
├── knowledge/                        - Reference materials
├── scripts/                          - Automation scripts
├── hooks/                            - PostToolUse hooks
└── assets/                           - Templates, schemas
```

## Token Comparison

| Version | SKILL.md Lines | Total Tokens | Per-Phase Load |
|---------|----------------|--------------|----------------|
| v2.2.2 | 2,261 | ~30,000 | 30,000 (all) |
| v3.0.0 | 308 | ~5,000 | ~10,000 (tier) |

**Reduction**: 86% fewer lines in SKILL.md, 67% fewer tokens per phase context

## Three-Tier Context Hierarchy

| Tier | File | Tokens | When Loaded |
|------|------|--------|-------------|
| **Global** | SKILL.md | ~5,000 | Always |
| **Workflow** | WORKFLOW.md | ~3,000 | Session start |
| **Phase** | phases/P{N}-*.md | ~2,000 each | Per phase |

## Key Design Principles

### 1. Progressive Disclosure

Instead of loading all 2,261 lines upfront, v3.0 loads:
- Global rules (always needed)
- Workflow contracts (at session start)
- Phase instructions (one at a time)

This reduces "Lost in the Middle" attention degradation.

### 2. Deterministic Enforcement

PostToolUse hooks automatically trigger `phase_data.py --phase-end` after every Write operation to `.phase_working/P{N}-*.md`. No reliance on LLM remembering to execute commands.

### 3. Data Contracts

Each phase has explicit input/output contracts defined in WORKFLOW.md:
- What data must be received from previous phase
- What data must be produced for next phase
- Required YAML block formats

### 4. Count Conservation

Formula: `P5.threats = P6.verified + P6.theoretical + P6.pending + P6.excluded`

Every threat from Phase 5 must be accounted for in Phase 6.

## Usage

### Session Start

```
1. Claude loads SKILL.md (auto)
2. Claude loads WORKFLOW.md (auto)
3. Creates 8 phase todos
```

### Per Phase

```
1. Read @phases/P{N}-*.md
2. Execute analysis per instructions
3. Write output to .phase_working/P{N}-*.md
4. Hook auto-validates (PostToolUse)
5. If pass: mark complete, continue
6. If fail: fix and rewrite
```

## Migration from v2.2.2

The v3.0 architecture is designed as a parallel implementation. Key differences:

| Aspect | v2.2.2 | v3.0.0 |
|--------|--------|--------|
| SKILL.md size | 2,261 lines | 308 lines |
| Phase instructions | Inline in SKILL.md | Separate files |
| Data contracts | Implicit | Explicit YAML schemas |
| Validation | Manual command | Automatic hooks |
| Context load | ~30K tokens upfront | ~10K per phase |

## Files Reference

| File | Purpose |
|------|---------|
| SKILL.md | Global constraints, output conventions, knowledge overview |
| WORKFLOW.md | Phase orchestration, data contracts, validation gates |
| phases/*.md | Detailed phase-by-phase execution instructions |
| contracts/*.yaml | Entity schemas, validation rules |
| scripts/phase_data.py | Data extraction and validation |
| hooks/phase_end_hook.sh | PostToolUse automation |

## Version History

- **v3.0.0** (2026-01-29): 5-pillar architectural redesign
- **v2.2.2** (2026-01-29): Session management, data protocols, complete discovery
- **v2.2.0** (2026-01-28): Phase output YAML blocks, validation integration

---

**License**: BSD-3-Clause
