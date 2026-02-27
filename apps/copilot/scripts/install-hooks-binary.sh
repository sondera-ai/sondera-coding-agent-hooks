#!/usr/bin/env bash
# Install Sondera Copilot hooks for production (using installed binary)
#
# This script creates a .github/hooks/hooks.json file in the current repository
# that uses the installed `sondera-copilot` binary.
#
# Prerequisites:
#   cargo install --path apps/copilot
#   or ensure sondera-copilot is in your PATH
#
# Usage:
#   ./install-hooks-binary.sh
#   ./install-hooks-binary.sh /path/to/repo

set -euo pipefail

# Determine the target repository
TARGET_REPO="${1:-.}"

# Resolve to absolute path
TARGET_REPO=$(cd "$TARGET_REPO" && pwd)

# Verify this is a git repository
if [ ! -d "$TARGET_REPO/.git" ]; then
    echo "Error: $TARGET_REPO is not a git repository"
    exit 1
fi

# Check if sondera-copilot is available
if ! command -v sondera-copilot &> /dev/null; then
    echo "Warning: sondera-copilot binary not found in PATH"
    echo "Install with: cargo install --path apps/copilot"
    echo ""
fi

# Create .github/hooks directory
HOOKS_DIR="$TARGET_REPO/.github/hooks"
mkdir -p "$HOOKS_DIR"

# Create hooks.json with binary commands
cat > "$HOOKS_DIR/hooks.json" << 'EOF'
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      {
        "type": "command",
        "bash": "sondera-copilot session-start",
        "powershell": "sondera-copilot.exe session-start",
        "cwd": ".",
        "timeoutSec": 30
      }
    ],
    "sessionEnd": [
      {
        "type": "command",
        "bash": "sondera-copilot session-end",
        "powershell": "sondera-copilot.exe session-end",
        "cwd": ".",
        "timeoutSec": 30
      }
    ],
    "userPromptSubmitted": [
      {
        "type": "command",
        "bash": "sondera-copilot user-prompt-submitted",
        "powershell": "sondera-copilot.exe user-prompt-submitted",
        "cwd": ".",
        "timeoutSec": 30
      }
    ],
    "preToolUse": [
      {
        "type": "command",
        "bash": "sondera-copilot pre-tool-use",
        "powershell": "sondera-copilot.exe pre-tool-use",
        "cwd": ".",
        "timeoutSec": 30
      }
    ],
    "postToolUse": [
      {
        "type": "command",
        "bash": "sondera-copilot post-tool-use",
        "powershell": "sondera-copilot.exe post-tool-use",
        "cwd": ".",
        "timeoutSec": 30
      }
    ],
    "errorOccurred": [
      {
        "type": "command",
        "bash": "sondera-copilot error-occurred",
        "powershell": "sondera-copilot.exe error-occurred",
        "cwd": ".",
        "timeoutSec": 30
      }
    ]
  }
}
EOF

echo "Installed Sondera Copilot hooks (production mode) to: $HOOKS_DIR/hooks.json"
echo ""
echo "Ensure sondera-copilot is in your PATH:"
echo "  cargo install --path apps/copilot"
