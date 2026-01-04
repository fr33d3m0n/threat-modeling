#!/bin/bash
# Code-First Deep Threat Modeling Workflow | Version 2.1.0 | https://github.com/fr33d3m0n/skill-threat-modeling | License: BSD-3-Clause | Welcome to cite but please retain all sources and declarations
# Multi-Platform Skill Path Detection Helper
#
# Supports:
#   - Multiple skill names: threat-modeling, skill-threat-modeling
#   - Multiple agent platforms: Claude, Qwen, Codex, Copilot, Goose, Cursor
#   - XDG-compliant portable paths
#
# Usage:
#   SKILL_PATH=$(bash skill_path.sh)
#   python "$SKILL_PATH/scripts/unified_kb_query.py" --stride spoofing
#
# Environment Variables:
#   SKILL_PATH      - Explicit path override (highest priority)
#   SKILL_PLATFORM  - Preferred platform: claude|qwen|codex|copilot|goose|cursor (optional)

# Supported skill directory names (GitHub clone vs standard install)
SKILL_NAMES=("threat-modeling" "skill-threat-modeling")

# Agent platform path patterns
# Project-local paths (checked in current directory)
PROJECT_LOCAL_PATTERNS=(
    ".claude/skills"      # Claude Code
    ".agents/skills"      # Portable (Agent Skills Standard)
    ".qwen/agents"        # Qwen Code
    ".codex/skills"       # OpenAI Codex
    ".github/skills"      # GitHub Copilot
    ".goose/skills"       # Goose
    ".cursor/skills"      # Cursor
)

# Global paths (checked in home directory)
GLOBAL_PATTERNS=(
    ".claude/skills"              # Claude Code
    ".config/agents/skills"       # XDG Portable (Recommended)
    ".qwen/agents"                # Qwen Code
    ".codex/skills"               # OpenAI Codex
    ".config/goose/skills"        # Goose (XDG)
)

# Function to check if a path is valid skill directory
is_valid_skill_dir() {
    local path="$1"
    # Check for SKILL.md (required) or scripts/ directory (optional but indicates valid skill)
    [ -f "$path/SKILL.md" ] || [ -d "$path/scripts" ]
}

# Function to find skill in a base directory with multiple name variants
find_skill_in_base() {
    local base="$1"
    for name in "${SKILL_NAMES[@]}"; do
        local check_path="$base/$name"
        if [ -d "$check_path" ] && is_valid_skill_dir "$check_path"; then
            echo "$check_path"
            return 0
        fi
    done
    return 1
}

# -------------------------------------------------------------------
# Priority 1: Environment variable override (highest priority)
# -------------------------------------------------------------------
if [ -n "$SKILL_PATH" ] && [ -d "$SKILL_PATH" ] && is_valid_skill_dir "$SKILL_PATH"; then
    echo "$SKILL_PATH"
    exit 0
fi

# -------------------------------------------------------------------
# Priority 2: Script self-location detection (always works for direct execution)
# -------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
if [ -n "$SCRIPT_DIR" ] && is_valid_skill_dir "$SCRIPT_DIR"; then
    echo "$SCRIPT_DIR"
    exit 0
fi

# -------------------------------------------------------------------
# Priority 3: Project-local installation (all supported platforms)
# -------------------------------------------------------------------
for pattern in "${PROJECT_LOCAL_PATTERNS[@]}"; do
    result=$(find_skill_in_base "$(pwd)/$pattern")
    if [ -n "$result" ]; then
        echo "$result"
        exit 0
    fi
done

# -------------------------------------------------------------------
# Priority 4: Global installation (all supported platforms)
# -------------------------------------------------------------------
for pattern in "${GLOBAL_PATTERNS[@]}"; do
    result=$(find_skill_in_base "$HOME/$pattern")
    if [ -n "$result" ]; then
        echo "$result"
        exit 0
    fi
done

# -------------------------------------------------------------------
# Not found - provide helpful error message
# -------------------------------------------------------------------
echo "Error: threat-modeling skill not found" >&2
echo "" >&2
echo "Installation locations checked:" >&2
echo "" >&2
echo "  Project-local (in current directory):" >&2
for pattern in "${PROJECT_LOCAL_PATTERNS[@]}"; do
    for name in "${SKILL_NAMES[@]}"; do
        echo "    - ./$pattern/$name" >&2
    done
done
echo "" >&2
echo "  Global (in home directory):" >&2
for pattern in "${GLOBAL_PATTERNS[@]}"; do
    for name in "${SKILL_NAMES[@]}"; do
        echo "    - ~/$pattern/$name" >&2
    done
done
echo "" >&2
echo "Solutions:" >&2
echo "  1. Install the skill to one of the above locations" >&2
echo "  2. Set SKILL_PATH environment variable: export SKILL_PATH=/path/to/skill" >&2
echo "  3. Run scripts directly from the skill directory" >&2
exit 1
