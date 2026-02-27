#!/usr/bin/env bash
set -euo pipefail

# Cursor Hooks Installation Script for Sondera
# This script installs Cursor hooks that integrate with the Sondera governance platform

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the directory where this script is located (apps/cursor/scripts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The Cargo.toml is in the parent directory (apps/cursor)
APP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Parse arguments
SCOPE="project"
PROJECT_DIR=""

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --user              Install to user scope (~/.cursor/hooks.json)"
    echo "  --project [DIR]     Install to project scope (<dir>/.cursor/hooks.json) [default]"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Scopes:"
    echo "  user     Global settings for all projects (~/.cursor/hooks.json)"
    echo "  project  Project-specific settings, committed to git (.cursor/hooks.json)"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --user)
            SCOPE="user"
            shift
            ;;
        --project)
            SCOPE="project"
            if [[ $# -gt 1 && ! "$2" =~ ^-- ]]; then
                PROJECT_DIR="$2"
                shift
            fi
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Determine hooks file path based on scope
case "${SCOPE}" in
    user)
        CURSOR_DIR="${HOME}/.cursor"
        HOOKS_FILE="${CURSOR_DIR}/hooks.json"
        ;;
    project)
        BASE_DIR="${PROJECT_DIR:-$(pwd)}"
        CURSOR_DIR="${BASE_DIR}/.cursor"
        HOOKS_FILE="${CURSOR_DIR}/hooks.json"
        ;;
esac

echo -e "${GREEN}Sondera Cursor Hooks Installer${NC}"
echo "================================"
echo ""
echo "Scope: ${SCOPE}"
echo "Hooks file: ${HOOKS_FILE}"
echo ""

# Create .cursor directory if it doesn't exist
if [ ! -d "${CURSOR_DIR}" ]; then
    echo "Creating ${CURSOR_DIR}..."
    mkdir -p "${CURSOR_DIR}"
fi

# Backup existing hooks.json if it exists
if [ -f "${HOOKS_FILE}" ]; then
    BACKUP_FILE="${HOOKS_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${YELLOW}Backing up existing hooks.json to ${BACKUP_FILE}${NC}"
    cp "${HOOKS_FILE}" "${BACKUP_FILE}"
fi

# Create hooks.json with all Cursor hook events
echo "Creating $(basename "${HOOKS_FILE}")..."
cat > "${HOOKS_FILE}" << EOF
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose session-start"
      }
    ],
    "sessionEnd": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose session-end"
      }
    ],
    "preToolUse": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose pre-tool-use",
        "matcher": "*"
      }
    ],
    "postToolUse": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose post-tool-use",
        "matcher": "*"
      }
    ],
    "postToolUseFailure": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose post-tool-use-failure",
        "matcher": "*"
      }
    ],
    "subagentStart": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose subagent-start"
      }
    ],
    "subagentStop": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose subagent-stop"
      }
    ],
    "beforeShellExecution": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose before-shell-execution"
      }
    ],
    "afterShellExecution": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose after-shell-execution"
      }
    ],
    "beforeMCPExecution": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose before-mcp-execution"
      }
    ],
    "afterMCPExecution": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose after-mcp-execution"
      }
    ],
    "beforeReadFile": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose before-read-file"
      }
    ],
    "afterFileEdit": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose after-file-edit"
      }
    ],
    "beforeSubmitPrompt": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose before-submit-prompt"
      }
    ],
    "afterAgentResponse": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose after-agent-response"
      }
    ],
    "afterAgentThought": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose after-agent-thought"
      }
    ],
    "preCompact": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose pre-compact"
      }
    ],
    "stop": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose stop"
      }
    ],
    "beforeTabFileRead": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose before-tab-file-read"
      }
    ],
    "afterTabFileEdit": [
      {
        "command": "cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml -- --verbose after-tab-file-edit"
      }
    ]
  }
}
EOF

echo -e "${GREEN}✓ Successfully created ${HOOKS_FILE}${NC}"
echo ""
echo "Configuration details:"
echo "  - Hook executable: cargo run --manifest-path ${APP_DIR}/Cargo.toml"
echo "  - Debug logging: enabled (--verbose flag)"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Restart Cursor to activate the hooks"
echo "  2. Check hook logs in stderr output (visible in Cursor's developer console)"
echo "  3. To view logs, open Cursor Developer Tools: Help → Toggle Developer Tools"
echo ""
echo -e "${GREEN}Installation complete!${NC}"
