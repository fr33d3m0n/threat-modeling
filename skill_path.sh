#!/bin/bash
# Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations
# Skill Path Detection Helper for threat-modeling skill
# Usage: SKILL_PATH=$(bash skill_path.sh)
#        python "$SKILL_PATH/scripts/unified_kb_query.py" --stride spoofing

# Priority: Project-local > Global > Script location

SKILL_NAME="threat-modeling"

# 1. Check project-local installation
if [ -d ".claude/skills/$SKILL_NAME" ]; then
    echo "$(pwd)/.claude/skills/$SKILL_NAME"
    exit 0
fi

# 2. Check global installation
if [ -d "$HOME/.claude/skills/$SKILL_NAME" ]; then
    echo "$HOME/.claude/skills/$SKILL_NAME"
    exit 0
fi

# 3. Check if running from skill directory itself
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/SKILL.md" ]; then
    echo "$SCRIPT_DIR"
    exit 0
fi

# 4. Check SKILL_PATH environment variable
if [ -n "$SKILL_PATH" ] && [ -d "$SKILL_PATH" ]; then
    echo "$SKILL_PATH"
    exit 0
fi

# Not found
echo "Error: $SKILL_NAME skill not found" >&2
echo "Install locations checked:" >&2
echo "  - ./.claude/skills/$SKILL_NAME" >&2
echo "  - ~/.claude/skills/$SKILL_NAME" >&2
exit 1
