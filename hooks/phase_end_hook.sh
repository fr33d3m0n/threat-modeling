#!/usr/bin/env bash
# Threat Modeling Skill | Version 3.0.0 (20260201b) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause

# =============================================================================
# STRIDE Threat Modeling - Phase End Protocol Hook
# =============================================================================
#
# Purpose: Automatically run phase_data.py --phase-end after each phase
#          report is written to .phase_working/P{N}-*.md
#
# Trigger: PostToolUse hook for Write tool
#
# Input: JSON via stdin from Claude Code
# {
#   "tool_name": "Write",
#   "tool_input": {
#     "file_path": "/path/to/.phase_working/P1-PROJECT-UNDERSTANDING.md",
#     "content": "..."
#   },
#   "tool_response": {
#     "filePath": "/path/to/.phase_working/P1-PROJECT-UNDERSTANDING.md",
#     "success": true
#   }
# }
#
# Output: JSON for Claude Code feedback
# =============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE_DATA_SCRIPT="${SCRIPT_DIR}/../scripts/phase_data.py"

# Logging function (to stderr for debugging, doesn't affect hook output)
log_debug() {
    if [[ "${STRIDE_HOOK_DEBUG:-false}" == "true" ]]; then
        echo "[phase_end_hook] $1" >&2
    fi
}

log_error() {
    echo "[phase_end_hook] ERROR: $1" >&2
}

# Read JSON input from stdin
INPUT_JSON=$(cat)

log_debug "Received input: ${INPUT_JSON:0:200}..."

# Parse JSON using jq
if ! command -v jq &> /dev/null; then
    log_error "jq is required but not installed"
    exit 0  # Non-blocking exit - let Claude continue
fi

# Extract relevant fields
TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // empty')
FILE_PATH=$(echo "$INPUT_JSON" | jq -r '.tool_input.file_path // empty')
SUCCESS=$(echo "$INPUT_JSON" | jq -r '.tool_response.success // false')

log_debug "Tool: $TOOL_NAME, File: $FILE_PATH, Success: $SUCCESS"

# Early exit conditions
if [[ "$TOOL_NAME" != "Write" ]]; then
    log_debug "Not a Write tool call, skipping"
    exit 0
fi

if [[ "$SUCCESS" != "true" ]]; then
    log_debug "Write was not successful, skipping"
    exit 0
fi

if [[ -z "$FILE_PATH" ]]; then
    log_debug "No file path provided, skipping"
    exit 0
fi

# =============================================================================
# Pattern Matching: Check if file is a phase report in .phase_working/
# =============================================================================
#
# Valid patterns:
#   - /path/to/Risk_Assessment_Report/.phase_working/P1-PROJECT-UNDERSTANDING.md
#   - /path/to/Risk_Assessment_Report/.phase_working/P2-DFD-ANALYSIS.md
#   - /path/to/Risk_Assessment_Report/.phase_working/P3-TRUST-BOUNDARY.md
#   - /path/to/Risk_Assessment_Report/.phase_working/P4-SECURITY-DESIGN-REVIEW.md
#   - /path/to/Risk_Assessment_Report/.phase_working/P5-STRIDE-THREATS.md
#   - /path/to/Risk_Assessment_Report/.phase_working/P6-RISK-VALIDATION.md
#   - /path/to/Risk_Assessment_Report/.phase_working/P7-MITIGATION-PLAN.md
#   - Also supports Chinese names like P1-项目理解.md
#
# Pattern: */.phase_working/P[1-8]-*.md
# =============================================================================

# Check if path contains .phase_working directory
if [[ ! "$FILE_PATH" =~ \.phase_working/ ]]; then
    log_debug "Not in .phase_working directory, skipping"
    exit 0
fi

# Extract filename from path
FILENAME=$(basename "$FILE_PATH")

# Check if filename matches P{N}-*.md pattern (P1 through P8)
if [[ ! "$FILENAME" =~ ^P([1-8])-.*\.md$ ]]; then
    log_debug "Filename doesn't match phase report pattern, skipping: $FILENAME"
    exit 0
fi

# Extract phase number from filename
PHASE_NUM="${BASH_REMATCH[1]}"
log_debug "Detected phase number: $PHASE_NUM"

# =============================================================================
# Derive Project Root
# =============================================================================
# Path structure: {PROJECT_ROOT}/Risk_Assessment_Report/.phase_working/P{N}-*.md
# We need to go up 2 levels from .phase_working to get PROJECT_ROOT

PHASE_WORKING_DIR=$(dirname "$FILE_PATH")
REPORT_DIR=$(dirname "$PHASE_WORKING_DIR")
PROJECT_ROOT=$(dirname "$REPORT_DIR")

log_debug "Derived project root: $PROJECT_ROOT"

# Validate project root exists
if [[ ! -d "$PROJECT_ROOT" ]]; then
    log_error "Derived project root doesn't exist: $PROJECT_ROOT"
    exit 0
fi

# =============================================================================
# Locate phase_data.py Script
# =============================================================================
# Priority order:
# 1. Script in same skill directory (../scripts/phase_data.py relative to hooks/)
# 2. Script in project's .claude/skills/threat-modeling/scripts/
# 3. Script in ~/.claude/skills/threat-modeling/scripts/

find_phase_data_script() {
    local locations=(
        "${SCRIPT_DIR}/../scripts/phase_data.py"
        "${PROJECT_ROOT}/.claude/skills/threat-modeling/scripts/phase_data.py"
        "${HOME}/.claude/skills/threat-modeling/scripts/phase_data.py"
    )

    for loc in "${locations[@]}"; do
        if [[ -f "$loc" ]]; then
            echo "$(realpath "$loc")"
            return 0
        fi
    done

    return 1
}

PHASE_DATA_SCRIPT=$(find_phase_data_script) || {
    log_error "Could not find phase_data.py script"
    exit 0
}

log_debug "Using phase_data.py: $PHASE_DATA_SCRIPT"

# =============================================================================
# Entry Gate Validation (Data Chain Integrity)
# =============================================================================
# For phases 2-8, verify that the upstream YAML data file exists
# This is an indirect check - if upstream YAML doesn't exist, the phase
# should not have been executed (Entry Gate violation)

validate_entry_gate() {
    local phase=$1
    local project_root=$2
    local session_dir

    # Find the session directory (most recent in .phase_working/)
    local phase_working_dir="${project_root}/Risk_Assessment_Report/.phase_working"

    if [[ ! -d "$phase_working_dir" ]]; then
        log_debug "No .phase_working directory found, skipping entry gate check"
        return 0
    fi

    # Find session directory (looking for data/ subdirectory)
    session_dir=$(find "$phase_working_dir" -maxdepth 2 -type d -name "data" 2>/dev/null | head -1 | xargs dirname 2>/dev/null || echo "")

    if [[ -z "$session_dir" || ! -d "$session_dir/data" ]]; then
        log_debug "No session data directory found, skipping entry gate check"
        return 0
    fi

    local data_dir="${session_dir}/data"

    # Phase 2+ requires upstream YAML
    if [[ $phase -ge 2 ]]; then
        local upstream_phase=$((phase - 1))
        local upstream_yaml

        case $upstream_phase in
            1) upstream_yaml="${data_dir}/P1_project_context.yaml" ;;
            2) upstream_yaml="${data_dir}/P2_dfd_elements.yaml" ;;
            3) upstream_yaml="${data_dir}/P3_boundary_context.yaml" ;;
            4) upstream_yaml="${data_dir}/P4_security_gaps.yaml" ;;
            5) upstream_yaml="${data_dir}/P5_threat_inventory.yaml" ;;
            6) upstream_yaml="${data_dir}/P6_validated_risks.yaml" ;;
            7) upstream_yaml="${data_dir}/P7_mitigation_plan.yaml" ;;
        esac

        if [[ -n "$upstream_yaml" && ! -f "$upstream_yaml" ]]; then
            log_error "ENTRY GATE VIOLATION: Phase $phase requires P${upstream_phase} YAML but file not found: $upstream_yaml"
            echo "ENTRY_GATE_VIOLATION"
            return 1
        fi

        log_debug "Entry gate passed: P${upstream_phase} YAML exists at $upstream_yaml"
    fi

    return 0
}

# Run entry gate validation
ENTRY_GATE_RESULT=$(validate_entry_gate "$PHASE_NUM" "$PROJECT_ROOT")
if [[ "$ENTRY_GATE_RESULT" == "ENTRY_GATE_VIOLATION" ]]; then
    cat <<EOF
{
    "hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": "⛔ ENTRY GATE VIOLATION: Phase $PHASE_NUM was executed but upstream Phase $((PHASE_NUM-1)) YAML data file is missing. This indicates Phase Isolation Protocol was bypassed. Please complete Phase $((PHASE_NUM-1)) first and ensure YAML data is written before proceeding."
    }
}
EOF
    exit 0
fi

# =============================================================================
# Execute Phase End Protocol
# =============================================================================
# Pass the absolute file path since the file is in .phase_working/
# phase_data.py will correctly handle absolute paths

log_debug "Executing: python3 $PHASE_DATA_SCRIPT --phase-end --phase $PHASE_NUM --file $FILE_PATH --root $PROJECT_ROOT"

# Run the phase end protocol and capture output
PHASE_END_OUTPUT=$(python3 "$PHASE_DATA_SCRIPT" \
    --phase-end \
    --phase "$PHASE_NUM" \
    --file "$FILE_PATH" \
    --root "$PROJECT_ROOT" 2>&1) || {
    EXIT_CODE=$?
    log_error "phase_data.py failed with exit code $EXIT_CODE"
    log_error "Output: $PHASE_END_OUTPUT"

    # Return structured error to Claude for awareness (non-blocking)
    cat <<EOF
{
    "hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": "Phase End Protocol Warning: phase_data.py returned error for Phase $PHASE_NUM. Error: ${PHASE_END_OUTPUT:0:500}"
    }
}
EOF
    exit 0
}

log_debug "Phase end protocol completed successfully"
log_debug "Output: ${PHASE_END_OUTPUT:0:500}..."

# =============================================================================
# Parse and Format Output for Claude
# =============================================================================
# phase_data.py returns JSON with extraction, validation, and summary results

# Extract key information from the JSON output
OVERALL_STATUS=$(echo "$PHASE_END_OUTPUT" | jq -r '.overall_status // "unknown"')
VALIDATION_STATUS=$(echo "$PHASE_END_OUTPUT" | jq -r '.validation.status // "unknown"')
NEXT_PHASE=$(echo "$PHASE_END_OUTPUT" | jq -r '.next_phase.number // empty')
NEXT_PHASE_QUERY=$(echo "$PHASE_END_OUTPUT" | jq -r '.next_phase.query_command // empty')

# Build context message for Claude
CONTEXT_MSG="Phase End Protocol executed for Phase $PHASE_NUM."

if [[ "$OVERALL_STATUS" == "success" ]]; then
    CONTEXT_MSG="$CONTEXT_MSG Status: SUCCESS."
elif [[ "$OVERALL_STATUS" == "warning" ]]; then
    CONTEXT_MSG="$CONTEXT_MSG Status: WARNING - Some validation issues detected."
elif [[ "$OVERALL_STATUS" == "blocking" ]]; then
    CONTEXT_MSG="$CONTEXT_MSG Status: BLOCKING - Critical validation failures."
fi

if [[ -n "$NEXT_PHASE" && "$NEXT_PHASE" != "null" ]]; then
    CONTEXT_MSG="$CONTEXT_MSG Next phase: $NEXT_PHASE."
fi

if [[ -n "$NEXT_PHASE_QUERY" && "$NEXT_PHASE_QUERY" != "null" ]]; then
    CONTEXT_MSG="$CONTEXT_MSG Query for next phase: python3 phase_data.py $NEXT_PHASE_QUERY"
fi

# Add validation details if there are issues
VALIDATION_ISSUES=$(echo "$PHASE_END_OUTPUT" | jq -r '.validation.issues // [] | length')
if [[ "$VALIDATION_ISSUES" -gt 0 ]]; then
    ISSUES_TEXT=$(echo "$PHASE_END_OUTPUT" | jq -r '.validation.issues | join("; ")' 2>/dev/null || echo "")
    if [[ -n "$ISSUES_TEXT" ]]; then
        CONTEXT_MSG="$CONTEXT_MSG Validation issues: $ISSUES_TEXT"
    fi
fi

# Return structured JSON output for Claude
cat <<EOF
{
    "hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": "$CONTEXT_MSG"
    }
}
EOF

exit 0
