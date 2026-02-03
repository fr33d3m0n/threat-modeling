# 4-Phase Gating Protocol Design for Threat Modeling Skill

## Overview

Upgrade from 3-step gate (PLANNING → EXECUTION → REFLECTION) to 4-step protocol:
**THINKING → PLANNING → EXECUTION LOOP → REFLECTION**

---

## Protocol Definition

### ① THINKING (Understanding Phase)

**Purpose**: Deep understanding BEFORE any planning. Prevents premature action.

**Threat Modeling Application**:
```yaml
thinking_checklist:
  core_problem:
    - "What is Phase {N}'s core objective in ONE sentence?"
    - "What security aspect does this phase address?"

  what_i_know:
    - "What data is available from P{N-1}_*.yaml?"
    - "What constraints apply (schema, validation rules)?"
    - "What patterns exist in the codebase (from discovery)?"

  what_i_dont_know:
    - "What gaps exist in input data?"
    - "What assumptions am I making?"
    - "What requires deeper investigation?"

  what_could_go_wrong:
    - "What would cause this phase to fail?"
    - "What edge cases might be missed?"
    - "What validation failures are likely?"

  stop_condition:
    - "If ANY question unanswered → STOP and clarify"
    - "If input data incomplete → STOP and report"
```

### ② PLANNING (Decomposition Phase)

**Purpose**: Break phase into verifiable sub-tasks AFTER understanding confirmed.

**Threat Modeling Application**:
```yaml
planning_checklist:
  objective_statement:
    - "Explicitly state: Phase {N} objective is..."
    - "Verify alignment with overall threat model goal"

  input_verification:
    - "Load P{N-1}_*.yaml from .phase_working/data/"
    - "Parse and validate structure"
    - "STOP if malformed or incomplete"

  sub_task_decomposition:
    - "Break into 3-7 discrete sub-tasks"
    - "Each sub-task must have:"
      - "Clear objective"
      - "Defined input (from upstream data or discovery)"
      - "Defined output (what gets written to YAML)"
      - "Verification criteria"

  task_creation:
    - "MANDATORY: Call TaskCreate for EACH sub-task"
    - "No implementation until TaskList shows all sub-tasks"
    - "Establish execution order (dependencies)"

  stop_condition:
    - "If decomposition unclear → return to THINKING"
    - "If TaskList incomplete → create remaining tasks"
```

### ③ EXECUTION LOOP (Implementation Phase)

**Purpose**: Execute each sub-task with verification and iteration.

**Threat Modeling Application**:
```yaml
execution_loop:
  for_each_subtask:
    step_1: "TaskUpdate(in_progress)"
    step_2: "Implement sub-task"
    step_3: "Verify: Does output match expected structure?"
    step_4:
      if_pass: "TaskUpdate(completed) → next sub-task"
      if_fail:
        - "Diagnose root cause"
        - "Fix the issue"
        - "Verify again (retry_count += 1)"
        - "If retry_count >= 3: CHECKPOINT → ask user"
        - "Once fixed: document error → TaskUpdate(completed)"

  data_write:
    primary: ".phase_working/{SESSION_ID}/data/P{N}_*.yaml"
    secondary: ".phase_working/{SESSION_ID}/reports/P{N}-*.md"
    order: "YAML first, then MD"

  validation:
    method: "PostToolUse hook runs phase_data.py --phase-end"
    on_failure: "Fix YAML, re-write, re-validate (up to 3 times)"

  checkpoint_phases:
    - "P5 (Threat Inventory): User confirms threat list before validation"
    - "P6 (Risk Validation): User confirms attack paths before mitigation"
    - "P7 (Mitigation Plan): User confirms remediation before report"
```

### ④ REFLECTION (Verification Phase)

**Purpose**: Confirm completeness and capture lessons BEFORE proceeding.

**Threat Modeling Application**:
```yaml
reflection_checklist:
  completeness_verification:
    - "All sub-tasks completed? (TaskList check)"
    - "All issues resolved? (no pending failures)"
    - "All YAML data written and validated? (exit code 0)"
    - "All required fields present? (schema compliance)"

  alignment_confirmation:
    - "Does output align with phase objective?"
    - "Does output support next phase's needs?"
    - "Is data traceable (input_ref field set)?"

  lessons_learned:
    - "What worked well in this phase?"
    - "What required iteration/retry?"
    - "What patterns should be reused?"
    - "Document in session notes (optional)"

  session_update:
    - "Update _session_meta.yaml:"
      - "phases.P{N}.status = 'completed'"
      - "phases.P{N}.completed_at = now()"
      - "phases.P{N}.data_file = path"
      - "phases.P{N}.report_file = path"

  proceed_condition:
    - "ALL verification passes → proceed to P{N+1}"
    - "ANY verification fails → iterate until pass"
```

---

## Phase-Specific Adaptations

### P1: Project Understanding

| Step | Content |
|------|---------|
| THINKING | What project type? What tech stack? What entry points exist? |
| PLANNING | Sub-tasks: module discovery, entry point scan, dependency analysis |
| EXECUTION | Run module_discovery.py, scan routes/handlers, build inventory |
| REFLECTION | All modules found? All entry types covered? 100% discovery checklist? |

### P2: DFD Analysis

| Step | Content |
|------|---------|
| THINKING | What interfaces exist? What data flows? What sensitive data? |
| PLANNING | Sub-tasks: interface inventory, data flow tracing, call flow mapping |
| EXECUTION | Trace each interface, map data flows, identify checkpoints |
| REFLECTION | L1 coverage 100%? All flows traced? Data stores identified? |

### P3: Trust Boundary

| Step | Content |
|------|---------|
| THINKING | What zones exist? What crosses boundaries? What protection exists? |
| PLANNING | Sub-tasks: boundary identification, interface mapping, risk classification |
| EXECUTION | Define boundaries, map cross-boundary flows, assess risks |
| REFLECTION | All boundaries defined? All flows mapped? Risk levels assigned? |

### P4: Security Design Review

| Step | Content |
|------|---------|
| THINKING | What controls exist? What's missing? What domains apply? |
| PLANNING | Sub-tasks: 16 domain assessment, gap identification, scoring |
| EXECUTION | Assess each domain, identify gaps, calculate scores |
| REFLECTION | All 16 domains covered? Gaps documented? Scores calculated? |

### P5: STRIDE Analysis

| Step | Content |
|------|---------|
| THINKING | What elements from DFD? What STRIDE categories apply? What KBs to query? |
| PLANNING | Sub-tasks: per-element STRIDE, KB queries, threat enumeration |
| EXECUTION | Apply STRIDE matrix, query CWE/CAPEC, build threat inventory |
| REFLECTION | All elements analyzed? All threats enumerated? KB queries logged? |
| **CHECKPOINT** | User confirms threat list before proceeding |

### P6: Risk Validation

| Step | Content |
|------|---------|
| THINKING | What threats to validate? What evidence exists? What POCs needed? |
| PLANNING | Sub-tasks: threat categorization, evidence collection, POC design, attack path construction |
| EXECUTION | Validate each threat, collect evidence, design POCs, build attack paths |
| REFLECTION | Count conservation balanced? All validated? Attack paths documented? |
| **CHECKPOINT** | User confirms risk assessment before mitigation |

### P7: Mitigation Planning

| Step | Content |
|------|---------|
| THINKING | What risks need mitigation? What controls available? What priority? |
| PLANNING | Sub-tasks: control mapping, implementation planning, roadmap creation |
| EXECUTION | Map mitigations to risks, plan implementations, build roadmap |
| REFLECTION | All VR-xxx have MIT-xxx? Roadmap complete? Verification defined? |
| **CHECKPOINT** | User confirms mitigation plan before report |

### P8: Report Generation

| Step | Content |
|------|---------|
| THINKING | What reports needed? What data sources? What format requirements? |
| PLANNING | Sub-tasks: report generation for each deliverable |
| EXECUTION | Generate each report from YAML data |
| REFLECTION | All required reports generated? Coverage validation passed? |

---

## Task Creation Mandate

**RULE**: Before ANY implementation, TaskList MUST show all sub-tasks.

```
WRONG:
1. Start implementing
2. Create task mid-way
3. Complete task

CORRECT:
1. THINKING: Understand phase
2. PLANNING: Decompose into sub-tasks
3. TaskCreate for ALL sub-tasks (before implementation)
4. TaskList shows complete plan
5. EXECUTION: For each sub-task in order:
   - TaskUpdate(in_progress)
   - Implement
   - Verify
   - TaskUpdate(completed)
6. REFLECTION: Verify all complete
```

---

## Verification Loop Protocol

```
retry_count = 0
MAX_RETRIES = 3

while verification_fails:
    diagnose_root_cause()
    fix_issue()
    verify_again()
    retry_count += 1

    if retry_count >= MAX_RETRIES:
        CHECKPOINT: Ask user for decision
        options:
          - "Continue trying"
          - "Skip this verification"
          - "Abort phase"
```

---

## Integration Points

1. **PostToolUse Hook**: Already validates YAML on Write
2. **phase_data.py --phase-end**: Runs validation
3. **_session_meta.yaml**: Tracks phase status
4. **TodoWrite/TaskCreate**: Track sub-tasks

---

*Design completed: 2026-02-01*
