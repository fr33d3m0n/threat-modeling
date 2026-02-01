<!-- Threat Modeling Skill | Version 3.0.0 (20260201a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Threat Modeling Skill - Claude Code Hooks

This directory contains PostToolUse hooks for automating the threat modeling workflow.

## Phase End Protocol Hook

**File:** `phase_end_hook.sh`

Automatically runs `phase_data.py --phase-end` after each phase report is written to `.phase_working/P{N}-*.md`.

### Trigger Conditions

The hook triggers when:
1. Tool name is `Write`
2. Write operation was successful (`success: true`)
3. File path contains `.phase_working/`
4. Filename matches pattern `P[1-8]-*.md` (e.g., `P1-PROJECT-UNDERSTANDING.md`)

### What It Does

1. **Extracts phase number** from the filename
2. **Derives project root** from the file path
3. **Locates phase_data.py** script (searches multiple locations)
4. **Executes Phase End Protocol** which:
   - Extracts YAML blocks from the phase report
   - Validates phase completion requirements
   - Generates summary for next phase handoff
   - Updates session state
5. **Returns feedback to Claude** via `additionalContext`

### Output Format

```json
{
    "hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": "Phase End Protocol executed for Phase 1. Status: SUCCESS. Next phase: 2. Query for next phase: python3 phase_data.py --query --phase 1 --summary --root /path/to/project"
    }
}
```

### Status Messages

- **SUCCESS**: All validation passed, ready for next phase
- **WARNING**: Some validation issues detected, review before proceeding
- **BLOCKING**: Critical validation failures, must fix before continuing

## Installation

### Option 1: Skill Integration (Recommended)

The hooks are automatically available when using the threat-modeling skill. The skill's `hooks.json` file configures the hook:

```json
{
  "description": "Threat Modeling Skill Hooks",
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "${CLAUDE_PLUGIN_ROOT}/hooks/phase_end_hook.sh",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

### Option 2: Global Settings

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/skills/threat-modeling/hooks/phase_end_hook.sh",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

### Option 3: Project Settings

Add to `.claude/settings.json` in your project:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/phase_end_hook.sh",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

## Requirements

- **jq**: Required for JSON parsing
- **Python 3**: Required to run phase_data.py
- **phase_data.py**: Must be accessible (hook searches multiple locations)

## Debugging

Enable debug mode by setting the environment variable:

```bash
export STRIDE_HOOK_DEBUG=true
```

Debug messages are written to stderr and won't affect the JSON output.

## Files

| File | Description |
|------|-------------|
| `phase_end_hook.sh` | Main hook script |
| `hooks.json` | Skill hook configuration |
| `settings-example.json` | Example settings.json configuration |
| `README.md` | This documentation |

## Input Format

The hook receives JSON from Claude Code via stdin:

```json
{
  "session_id": "abc123",
  "transcript_path": "/path/to/transcript.jsonl",
  "cwd": "/current/working/directory",
  "permission_mode": "default",
  "hook_event_name": "PostToolUse",
  "tool_name": "Write",
  "tool_input": {
    "file_path": "/path/to/Risk_Assessment_Report/.phase_working/P1-PROJECT-UNDERSTANDING.md",
    "content": "# Phase 1 Report..."
  },
  "tool_response": {
    "filePath": "/path/to/Risk_Assessment_Report/.phase_working/P1-PROJECT-UNDERSTANDING.md",
    "success": true
  },
  "tool_use_id": "toolu_01ABC123..."
}
```

## Error Handling

- All errors are non-blocking (exit code 0) to not interrupt Claude's workflow
- Errors are reported via `additionalContext` for Claude's awareness
- Debug/error messages go to stderr, not stdout
- Missing jq or phase_data.py results in silent skip
