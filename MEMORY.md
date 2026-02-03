# MEMORY.md - Project Memory for AI Assistants

> **Last Updated**: 2026-02-03
> **Current Version**: 3.0.1 (20260203a)

---

## Recent Changes (v3.0.1)

### Architecture Optimization
- **SKILL.md/WORKFLOW.md 职责分离**:
  - SKILL.md = "WHAT & WHY" (静态契约)
  - WORKFLOW.md = "HOW & WHEN" (动态协议)
- **FSM 形式化**: 8阶段工作流状态机定义
- **4-Gate 子状态机**: 每阶段内部执行协议
- **Token 优化**: 26.4% reduction (12K → 8.8K)

### Version Release (2026-02-03)
- Archived: v3.0.0 → `Archive/v3.0.0/`
- Updated: v3.0.1 across Dev, Release, Local Install
- Pending: GitHub push (awaiting user approval)

---

## Key Architecture Decisions

### 1. File Responsibility Separation

| File | Content | Should NOT Contain |
|------|---------|-------------------|
| SKILL.md | Version, Concepts, Constraints, Data Model | Execution steps, Phase flow details |
| WORKFLOW.md | Session lifecycle, FSM, Data contracts, Validation | Version info, Repeated definitions |

### 2. Cross-Reference Convention

```markdown
> **Execution Protocol Details**: See WORKFLOW.md §2
```
代替重复内容，保持单一事实源。

### 3. FSM Definition

```
States: {INIT, P1-P8, DONE, ERROR}
Accepting: {DONE}
Transitions: δ(Pn, pn_complete) → P(n+1)
```

---

## Project Paths

```
Development:   /home/elly/STRIDE/threat-modeling/
Release:       /home/elly/STRIDE/Release/threat-modeling/
Local Install: /home/elly/.claude/skills/threat-modeling/
Archive:       /home/elly/STRIDE/Archive/
Test Projects: /home/elly/STRIDE/test/
```

---

## Version Management Rules

| Component | Auto-Change | Example |
|-----------|-------------|---------|
| X.Y.Z | ❌ NO (需用户授权) | 3.0.1 → 3.0.2 |
| Date suffix | ✅ YES | (20260203a) → (20260203b) |

---

## Pending Items

1. [ ] Push v3.0.1 to GitHub (awaiting user confirmation)
2. [ ] Update CHANGELOG.md for v3.0.1
3. [ ] Full test suite validation

---

## Session Checkpoints

- `tmp_data/SESSION_CHECKPOINT_20260203.md` - Latest session details
