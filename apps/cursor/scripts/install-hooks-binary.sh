#!/usr/bin/env bash
set -euo pipefail

# Cursor Hooks Installation Script for Sondera (Binary Version)
# This script installs Cursor hooks using the installed sondera-cursor binary

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# Detect binary location
BINARY_PATH=""
if command -v sondera-cursor &> /dev/null; then
    BINARY_PATH="sondera-cursor"
elif [ -f "${HOME}/.cargo/bin/sondera-cursor" ]; then
    BINARY_PATH="${HOME}/.cargo/bin/sondera-cursor"
elif [ -f "/usr/local/bin/sondera-cursor" ]; then
    BINARY_PATH="/usr/local/bin/sondera-cursor"
else
    echo -e "${RED}Error: sondera-cursor binary not found${NC}"
    echo "Please install it first using:"
    echo "  cargo install --path apps/cursor"
    echo "Or ensure it's in your PATH"
    exit 1
fi

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

echo -e "${GREEN}Sondera Cursor Hooks Installer (Binary)${NC}"
echo "========================================"
echo ""
echo "Using binary: ${BINARY_PATH}"
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
        "command": "${BINARY_PATH} --verbose session-start"
      }
    ],
    "sessionEnd": [
      {
        "command": "${BINARY_PATH} --verbose session-end"
      }
    ],
    "preToolUse": [
      {
        "command": "${BINARY_PATH} --verbose pre-tool-use",
        "matcher": "*"
      }
    ],
    "postToolUse": [
      {
        "command": "${BINARY_PATH} --verbose post-tool-use",
        "matcher": "*"
      }
    ],
    "postToolUseFailure": [
      {
        "command": "${BINARY_PATH} --verbose post-tool-use-failure",
        "matcher": "*"
      }
    ],
    "subagentStart": [
      {
        "command": "${BINARY_PATH} --verbose subagent-start"
      }
    ],
    "subagentStop": [
      {
        "command": "${BINARY_PATH} --verbose subagent-stop"
      }
    ],
    "beforeShellExecution": [
      {
        "command": "${BINARY_PATH} --verbose before-shell-execution"
      }
    ],
    "afterShellExecution": [
      {
        "command": "${BINARY_PATH} --verbose after-shell-execution"
      }
    ],
    "beforeMCPExecution": [
      {
        "command": "${BINARY_PATH} --verbose before-mcp-execution"
      }
    ],
    "afterMCPExecution": [
      {
        "command": "${BINARY_PATH} --verbose after-mcp-execution"
      }
    ],
    "beforeReadFile": [
      {
        "command": "${BINARY_PATH} --verbose before-read-file"
      }
    ],
    "afterFileEdit": [
      {
        "command": "${BINARY_PATH} --verbose after-file-edit"
      }
    ],
    "beforeSubmitPrompt": [
      {
        "command": "${BINARY_PATH} --verbose before-submit-prompt"
      }
    ],
    "afterAgentResponse": [
      {
        "command": "${BINARY_PATH} --verbose after-agent-response"
      }
    ],
    "afterAgentThought": [
      {
        "command": "${BINARY_PATH} --verbose after-agent-thought"
      }
    ],
    "preCompact": [
      {
        "command": "${BINARY_PATH} --verbose pre-compact"
      }
    ],
    "stop": [
      {
        "command": "${BINARY_PATH} --verbose stop"
      }
    ],
    "beforeTabFileRead": [
      {
        "command": "${BINARY_PATH} --verbose before-tab-file-read"
      }
    ],
    "afterTabFileEdit": [
      {
        "command": "${BINARY_PATH} --verbose after-tab-file-edit"
      }
    ]
  }
}
EOF

echo -e "${GREEN}✓ Successfully created ${HOOKS_FILE}${NC}"
echo ""
echo "Configuration details:"
echo "  - Hook executable: ${BINARY_PATH}"
echo "  - Debug logging: enabled (--verbose flag)"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Restart Cursor to activate the hooks"
echo "  2. Check hook logs in stderr output (visible in Cursor's developer console)"
echo "  3. To view logs, open Cursor Developer Tools: Help → Toggle Developer Tools"
echo ""
echo -e "${GREEN}Installation complete!${NC}"
