#!/usr/bin/env bash
set -euo pipefail

# Gemini CLI Hooks Installation Script for Sondera
# This script installs Gemini CLI hooks that integrate with the Sondera governance platform

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where this script is located (apps/gemini/scripts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The Cargo.toml is in the parent directory (apps/gemini)
APP_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Parse arguments
SCOPE="local"
PROJECT_DIR=""

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --user              Install to user scope (~/.gemini/settings.json)"
    echo "  --project [DIR]     Install to project scope (<dir>/.gemini/settings.json)"
    echo "  --local [DIR]       Install to local scope (<dir>/.gemini/settings.local.json) [default]"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Scopes:"
    echo "  user     Global settings for all projects (~/.gemini/settings.json)"
    echo "  project  Project-specific settings, committed to git (.gemini/settings.json)"
    echo "  local    Project-specific settings, NOT committed to git (.gemini/settings.local.json)"
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

# Determine settings file path based on scope
case "${SCOPE}" in
    user)
        GEMINI_DIR="${HOME}/.gemini"
        SETTINGS_FILE="${GEMINI_DIR}/settings.json"
        ;;
    project)
        BASE_DIR="${PROJECT_DIR:-$(pwd)}"
        GEMINI_DIR="${BASE_DIR}/.gemini"
        SETTINGS_FILE="${GEMINI_DIR}/settings.json"
        ;;
    local)
        BASE_DIR="${PROJECT_DIR:-$(pwd)}"
        GEMINI_DIR="${BASE_DIR}/.gemini"
        SETTINGS_FILE="${GEMINI_DIR}/settings.local.json"
        ;;
esac

# Build the command path
HOOK_CMD="cargo run --quiet --manifest-path ${APP_DIR}/Cargo.toml --"

echo -e "${GREEN}Sondera Gemini CLI Hooks Installer${NC}"
echo "===================================="
echo ""
echo "Scope: ${SCOPE}"
echo "Settings file: ${SETTINGS_FILE}"
echo ""

# Create .gemini directory if it doesn't exist
if [ ! -d "${GEMINI_DIR}" ]; then
    echo "Creating ${GEMINI_DIR}..."
    mkdir -p "${GEMINI_DIR}"
fi

# Backup existing settings file if it exists
if [ -f "${SETTINGS_FILE}" ]; then
    BACKUP_FILE="${SETTINGS_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${YELLOW}Backing up existing settings to ${BACKUP_FILE}${NC}"
    cp "${SETTINGS_FILE}" "${BACKUP_FILE}"
fi

# Create settings file with all Gemini CLI hook events
echo "Creating $(basename "${SETTINGS_FILE}")..."
cat > "${SETTINGS_FILE}" << EOF
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "name": "sondera-session-start",
            "type": "command",
            "command": "${HOOK_CMD} session-start",
            "description": "Initialize Sondera trajectory for session",
            "timeout": 30000
          }
        ]
      }
    ],
    "SessionEnd": [
      {
        "hooks": [
          {
            "name": "sondera-session-end",
            "type": "command",
            "command": "${HOOK_CMD} session-end",
            "description": "Finalize Sondera trajectory for session",
            "timeout": 30000
          }
        ]
      }
    ],
    "BeforeAgent": [
      {
        "hooks": [
          {
            "name": "sondera-before-agent",
            "type": "command",
            "command": "${HOOK_CMD} before-agent",
            "description": "Validate user prompt with Sondera policies",
            "timeout": 30000
          }
        ]
      }
    ],
    "AfterAgent": [
      {
        "hooks": [
          {
            "name": "sondera-after-agent",
            "type": "command",
            "command": "${HOOK_CMD} after-agent",
            "description": "Audit agent response with Sondera",
            "timeout": 30000
          }
        ]
      }
    ],
    "BeforeModel": [
      {
        "hooks": [
          {
            "name": "sondera-before-model",
            "type": "command",
            "command": "${HOOK_CMD} before-model",
            "description": "Validate LLM request with Sondera policies",
            "timeout": 30000
          }
        ]
      }
    ],
    "AfterModel": [
      {
        "hooks": [
          {
            "name": "sondera-after-model",
            "type": "command",
            "command": "${HOOK_CMD} after-model",
            "description": "Audit LLM response with Sondera",
            "timeout": 30000
          }
        ]
      }
    ],
    "BeforeToolSelection": [
      {
        "hooks": [
          {
            "name": "sondera-before-tool-selection",
            "type": "command",
            "command": "${HOOK_CMD} before-tool-selection",
            "description": "Filter available tools with Sondera policies",
            "timeout": 30000
          }
        ]
      }
    ],
    "BeforeTool": [
      {
        "matcher": "*",
        "hooks": [
          {
            "name": "sondera-before-tool",
            "type": "command",
            "command": "${HOOK_CMD} before-tool",
            "description": "Validate tool execution with Sondera policies",
            "timeout": 30000
          }
        ]
      }
    ],
    "AfterTool": [
      {
        "matcher": "*",
        "hooks": [
          {
            "name": "sondera-after-tool",
            "type": "command",
            "command": "${HOOK_CMD} after-tool",
            "description": "Audit tool results with Sondera",
            "timeout": 30000
          }
        ]
      }
    ],
    "PreCompress": [
      {
        "hooks": [
          {
            "name": "sondera-pre-compress",
            "type": "command",
            "command": "${HOOK_CMD} pre-compress",
            "description": "Log context compression events",
            "timeout": 10000
          }
        ]
      }
    ],
    "Notification": [
      {
        "hooks": [
          {
            "name": "sondera-notification",
            "type": "command",
            "command": "${HOOK_CMD} notification",
            "description": "Forward system notifications to Sondera",
            "timeout": 10000
          }
        ]
      }
    ]
  }
}
EOF

echo -e "${GREEN}✓ Successfully created ${SETTINGS_FILE}${NC}"
echo ""
echo -e "${BLUE}Configuration details:${NC}"
echo "  - Hook executable: cargo run --manifest-path ${APP_DIR}/Cargo.toml"
echo "  - Settings location: ${SETTINGS_FILE}"
echo "  - Timeout: 30 seconds per hook (10s for advisory hooks)"
echo ""
echo -e "${BLUE}Installed hooks:${NC}"
echo "  - SessionStart    - Initialize trajectory on session start"
echo "  - SessionEnd      - Finalize trajectory on session end"
echo "  - BeforeAgent     - Validate user prompts"
echo "  - AfterAgent      - Audit agent responses"
echo "  - BeforeModel     - Validate LLM requests"
echo "  - AfterModel      - Audit LLM responses"
echo "  - BeforeToolSelection - Filter available tools"
echo "  - BeforeTool      - Validate tool execution"
echo "  - AfterTool       - Audit tool results"
echo "  - PreCompress     - Log context compression"
echo "  - Notification    - Forward system notifications"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Restart Gemini CLI to activate the hooks"
echo "  2. Check hook logs in stderr output"
echo ""
echo -e "${BLUE}Managing hooks:${NC}"
echo "  - View hooks:     /hooks panel"
echo "  - Enable all:     /hooks enable-all"
echo "  - Disable all:    /hooks disable-all"
echo "  - Enable one:     /hooks enable <name>"
echo "  - Disable one:    /hooks disable <name>"
echo ""
echo -e "${GREEN}Installation complete!${NC}"
