# WORKFLOW.md - Orchestration Contracts

**Version**: 3.0.0
**Purpose**: Phase orchestration, data contracts, validation gates

---

## §1 Session Initialization

### Todo Creation

Create 8 items at session start:

```json
[
  {"content": "Phase 1: Project Understanding", "status": "pending", "activeForm": "分析项目架构和技术栈"},
  {"content": "Phase 2: Call Flow & DFD Analysis", "status": "pending", "activeForm": "构建数据流图"},
  {"content": "Phase 3: Trust Boundary Evaluation", "status": "pending", "activeForm": "识别信任边界"},
  {"content": "Phase 4: Security Design Review", "status": "pending", "activeForm": "评估安全设计"},
  {"content": "Phase 5: STRIDE Threat Analysis", "status": "pending", "activeForm": "执行STRIDE分析"},
  {"content": "Phase 6: Risk Validation", "status": "pending", "activeForm": "验证风险和攻击路径"},
  {"content": "Phase 7: Mitigation Planning", "status": "pending", "activeForm": "制定缓解措施"},
  {"content": "Phase 8: Report Generation", "status": "pending", "activeForm": "生成威胁建模报告"}
]
```

### Session Recovery

Check `.phase_working/`:
- Exists + project_name matches → Prompt: "Continue or restart?"
- Exists + project_name differs → Clear and restart
- Not exists → Create and start new

---

## §2 Phase Data Contracts

### P1 → P2: project_context

```yaml
# Contract: P1 output must provide
project_context:
  project_type: "web|api|microservices|ai|llm"
  modules: []           # From yaml:module_inventory
  entry_points: []      # From yaml:entry_point_inventory
  security_design: {}   # Preliminary security observations
```

**Required YAML Blocks in P1 Output**:
- `yaml:module_inventory` (MANDATORY)
- `yaml:entry_point_inventory` (MANDATORY)
- `yaml:discovery_checklist` (MANDATORY)
- `yaml:doc_analysis` (if documentation exists)

### P2 → P3: dfd_elements

```yaml
# Contract: P2 output must provide
dfd_elements:
  external_interactors: []  # EI-xxx
  processes: []             # P-xxx
  data_stores: []           # DS-xxx
  data_flows: []            # DF-xxx
  l1_coverage:
    total_entry_points: N
    analyzed: N
    coverage_percentage: 100  # MUST be 100
```

**Required YAML Blocks in P2 Output**:
- `yaml:dfd_elements` (MANDATORY)
- `yaml:data_flows` (MANDATORY with l1_coverage)

### P3 → P4: boundary_context

```yaml
# Contract: P3 output must provide
boundary_context:
  boundaries: []        # TB-xxx with type and scope
  interfaces: []        # Cross-boundary interfaces
  data_nodes: []        # Sensitive data locations
  cross_boundary_flows: []
```

### P4 → P5: security_gaps

```yaml
# Contract: P4 output must provide
security_gaps:
  gaps: []              # {domain, severity, description}
  design_matrix: {}     # 16-domain assessment
```

### P5 → P6: threat_inventory

```yaml
# Contract: P5 output must provide
threat_inventory:
  threats: []           # T-{STRIDE}-{Element}-{Seq}
  summary:
    total: N
    by_stride: {S: N, T: N, R: N, I: N, D: N, E: N}
    by_element_type: {process: N, datastore: N, dataflow: N}
```

**Required YAML Blocks in P5 Output**:
- `yaml:threat_inventory` (MANDATORY)

### P6 → P7: validated_risks

```yaml
# Contract: P6 output must provide
validated_risks:
  risk_summary:
    total_identified: N
    total_verified: N
    total_theoretical: N
    total_pending: N
    total_excluded: N
  risk_details: []      # VR-xxx with threat_refs[]
  poc_details: []       # POC-xxx for Critical/High
  attack_paths: []      # AP-xxx with feasibility
  attack_chains: []     # AC-xxx with steps
```

**Required YAML Blocks in P6 Output**:
- `yaml:validated_risks` (MANDATORY)
- `yaml:poc_details` (MANDATORY for Critical/High)
- `yaml:attack_chains` (MANDATORY)

### P7 → P8: mitigation_plan

```yaml
# Contract: P7 output must provide
mitigation_plan:
  mitigations: []       # MIT-xxx with risk_refs[]
  roadmap:
    immediate: []       # P0 fixes
    short_term: []      # P1 fixes (7 days)
    medium_term: []     # P2 fixes (30 days)
    long_term: []       # P3 improvements
```

**Required YAML Blocks in P7 Output**:
- `yaml:mitigation_plan` (MANDATORY)

---

## §3 Validation Gates

### Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Pass | Proceed to next phase |
| 1 | Missing data | Fix and revalidate |
| 2 | Validation failed | Review requirements |

### Phase-Specific Validation

| Phase | Validation Command | Pass Criteria |
|-------|-------------------|---------------|
| 1 | `--phase-end --phase 1` | 3 YAML blocks, checklist 100% |
| 2 | `--phase-end --phase 2` | DFD elements, L1 coverage 100% |
| 3 | `--phase-end --phase 3` | Trust boundaries defined |
| 4 | `--phase-end --phase 4` | Security gaps documented |
| 5 | `--phase-end --phase 5` | Threat inventory present |
| 6 | `--phase-end --phase 6` | Risks validated, count conserved |
| 7 | `--phase-end --phase 7` | Mitigation plan present |
| 8 | `--phase-end --phase 8` | All 8 reports generated |

### Count Conservation Formula

```
P5.threat_inventory.total =
  P6.verified + P6.theoretical + P6.pending + P6.excluded
```

Validation fails if formula doesn't balance.

---

## §4 STRIDE per Element Matrix

| Element Type | S | T | R | I | D | E |
|--------------|---|---|---|---|---|---|
| Process      | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data Store   |   | ✓ | ✓ | ✓ | ✓ |   |
| Data Flow    |   | ✓ |   | ✓ | ✓ |   |
| External (source) | ✓ |   | ✓ |   |   |   |

---

## §5 Phase Context Protocol

Each phase must declare:

1. **Input Context**: What data from previous phase(s) is required
2. **Knowledge Reference**: Which knowledge sets to query
3. **Output Context**: What data to produce for next phase

### Context Loading Pattern

```
Phase N starts:
  1. Read @phases/P{N}-*.md           # Phase instructions
  2. Load previous phase output       # Input context
  3. Query knowledge base as needed   # Progressive loading
  4. Execute analysis                 # LLM work
  5. Write output                     # Hook validates
```

---

## §6 Report Generation (Phase 8)

### Required Reports (8)

| Report | Template | Content |
|--------|----------|---------|
| RISK-ASSESSMENT-REPORT.md | Main report | Executive summary + all sections |
| RISK-INVENTORY.md | Risk list | All VR-xxx entries |
| MITIGATION-MEASURES.md | Remediation | All MIT-xxx entries |
| PENETRATION-TEST-PLAN.md | Pentest | POC-based test plan |
| ARCHITECTURE-ANALYSIS.md | Architecture | P1-P3 synthesis |
| DFD-DIAGRAM.md | DFD | Mermaid diagrams |
| COMPLIANCE-REPORT.md | Compliance | Framework mapping |
| ATTACK-PATH-VALIDATION.md | Attacks | AC-xxx chains |

### Phase Output Publication

Copy from `.phase_working/` to `Risk_Assessment_Report/`:
- P1-PROJECT-UNDERSTANDING.md
- P2-DFD-ANALYSIS.md
- P3-TRUST-BOUNDARY.md
- P4-SECURITY-DESIGN-REVIEW.md
- P5-STRIDE-THREATS.md
- P6-RISK-VALIDATION.md

---

## §7 Knowledge Query Reference

### By Phase

| Phase | Primary Queries |
|-------|-----------------|
| 1 | `--doc-analysis` (script) |
| 2 | security-design.yaml |
| 3 | security-design.yaml |
| 4 | `--control {domain}`, `--stride-controls` |
| 5 | `--stride`, `--full-chain CWE-xxx` |
| 6 | `--capec`, `--attack-technique`, `--stride-tests` |
| 7 | `--cwe --mitigations`, `--asvs-level` |
| 8 | `--compliance`, `--asvs-chapter` |

---

## §8 Error Recovery

### Validation Failure

1. Read error message from hook output
2. Identify missing/invalid data
3. Supplement analysis
4. Rewrite phase output
5. Hook re-validates automatically

### Session Interruption

1. Check `.phase_working/_session_meta.yaml`
2. Identify last completed phase
3. Resume from next phase
4. All previous phase data preserved in YAML files

---

**End of WORKFLOW.md** (~250 lines, ~3K tokens)
