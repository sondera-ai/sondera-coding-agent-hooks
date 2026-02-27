#!/usr/bin/env bash
set -euo pipefail

# Claude Code Hooks Installation Script for Sondera (Binary Version)
# This script installs Claude Code hooks using the installed sondera-claude binary
# Note: Hooks connect to the harness server via Unix socket IPC

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
SCOPE="local"
PROJECT_DIR=""

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --user              Install to user scope (~/.claude/settings.json)"
    echo "  --project [DIR]     Install to project scope (<dir>/.claude/settings.json)"
    echo "  --local [DIR]       Install to local scope (<dir>/.claude/settings.local.json) [default]"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Scopes:"
    echo "  user     Global settings for all projects (~/.claude/settings.json)"
    echo "  project  Project-specific settings, committed to git (.claude/settings.json)"
    echo "  local    Project-specific settings, NOT committed to git (.claude/settings.local.json)"
    echo ""
    echo "Note: The harness server must be running for hooks to function."
    echo "      Start it with: sondera-harness-server"
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
        --local)
            SCOPE="local"
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
if command -v sondera-claude &> /dev/null; then
    BINARY_PATH="sondera-claude"
elif [ -f "${HOME}/.cargo/bin/sondera-claude" ]; then
    BINARY_PATH="${HOME}/.cargo/bin/sondera-claude"
elif [ -f "/usr/local/bin/sondera-claude" ]; then
    BINARY_PATH="/usr/local/bin/sondera-claude"
else
    echo -e "${RED}Error: sondera-claude binary not found${NC}"
    echo "Please install it first using:"
    echo "  cargo install --path apps/claude"
    echo "Or ensure it's in your PATH"
    exit 1
fi

# Determine settings file path based on scope
case "${SCOPE}" in
    user)
        CLAUDE_DIR="${HOME}/.claude"
        SETTINGS_FILE="${CLAUDE_DIR}/settings.json"
        ;;
    project)
        BASE_DIR="${PROJECT_DIR:-$(pwd)}"
        CLAUDE_DIR="${BASE_DIR}/.claude"
        SETTINGS_FILE="${CLAUDE_DIR}/settings.json"
        ;;
    local)
        BASE_DIR="${PROJECT_DIR:-$(pwd)}"
        CLAUDE_DIR="${BASE_DIR}/.claude"
        SETTINGS_FILE="${CLAUDE_DIR}/settings.local.json"
        ;;
esac

echo -e "${GREEN}Sondera Claude Code Hooks Installer (Binary)${NC}"
echo "============================================="
echo ""
echo "Using binary: ${BINARY_PATH}"
echo "Scope: ${SCOPE}"
echo "Settings file: ${SETTINGS_FILE}"
echo ""

# Create .claude directory if it doesn't exist
if [ ! -d "${CLAUDE_DIR}" ]; then
    echo "Creating ${CLAUDE_DIR}..."
    mkdir -p "${CLAUDE_DIR}"
fi

# Backup existing settings file if it exists
if [ -f "${SETTINGS_FILE}" ]; then
    BACKUP_FILE="${SETTINGS_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${YELLOW}Backing up existing settings to ${BACKUP_FILE}${NC}"
    cp "${SETTINGS_FILE}" "${BACKUP_FILE}"
fi

# Create settings file with all Claude Code hook events
echo "Creating $(basename "${SETTINGS_FILE}")..."
cat > "${SETTINGS_FILE}" << EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose pre-tool-use"
          }
        ]
      }
    ],
    "PermissionRequest": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose permission-request"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose post-tool-use"
          }
        ]
      }
    ],
    "PostToolUseFailure": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose post-tool-use-failure"
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose user-prompt-submit"
          }
        ]
      }
    ],
    "Notification": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose notification"
          }
        ]
      }
    ],
    "Stop": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose stop"
          }
        ]
      }
    ],
    "SubagentStart": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose subagent-start"
          }
        ]
      }
    ],
    "SubagentStop": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose subagent-stop"
          }
        ]
      }
    ],
    "TeammateIdle": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose teammate-idle"
          }
        ]
      }
    ],
    "TaskCompleted": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose task-completed"
          }
        ]
      }
    ],
    "PreCompact": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose pre-compact"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose session-start"
          }
        ]
      }
    ],
    "SessionEnd": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "${BINARY_PATH} --verbose session-end"
          }
        ]
      }
    ]
  }
}
EOF

echo -e "${GREEN}✓ Successfully created ${SETTINGS_FILE}${NC}"
echo ""
echo "Configuration details:"
echo "  - Hook executable: ${BINARY_PATH}"
echo "  - Debug logging: enabled (--verbose flag)"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Start the harness server: sondera-harness-server"
echo "  2. Restart Claude Code to activate the hooks"
echo "  3. Check hook logs in stderr output"
echo ""
echo -e "${GREEN}Installation complete!${NC}"
