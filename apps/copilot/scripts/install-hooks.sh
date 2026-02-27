#!/usr/bin/env bash
# Install Sondera Copilot hooks for development (using cargo run)
#
# This script creates a .github/hooks/hooks.json file in the current repository
# that uses `cargo run` to execute the hooks, useful for development and testing.
#
# Usage:
#   ./install-hooks.sh
#   ./install-hooks.sh /path/to/repo

set -euo pipefail

# Determine the target repository
TARGET_REPO="${1:-.}"

# Resolve to absolute path
TARGET_REPO=$(cd "$TARGET_REPO" && pwd)

# Get the workspace root (where Cargo.toml is)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Verify this is a git repository
if [ ! -d "$TARGET_REPO/.git" ]; then
    echo "Error: $TARGET_REPO is not a git repository"
    exit 1
fi

# Create .github/hooks directory
HOOKS_DIR="$TARGET_REPO/.github/hooks"
mkdir -p "$HOOKS_DIR"

# Create hooks.json with cargo run commands
cat > "$HOOKS_DIR/hooks.json" << EOF
{
  "version": 1,
  "hooks": {
    "sessionStart": [
      {
        "type": "command",
        "bash": "cargo run --manifest-path $WORKSPACE_ROOT/Cargo.toml -p sondera-copilot -- session-start",
        "cwd": ".",
        "timeoutSec": 60
      }
    ],
    "sessionEnd": [
      {
        "type": "command",
        "bash": "cargo run --manifest-path $WORKSPACE_ROOT/Cargo.toml -p sondera-copilot -- session-end",
        "cwd": ".",
        "timeoutSec": 60
      }
    ],
    "userPromptSubmitted": [
      {
        "type": "command",
        "bash": "cargo run --manifest-path $WORKSPACE_ROOT/Cargo.toml -p sondera-copilot -- user-prompt-submitted",
        "cwd": ".",
        "timeoutSec": 60
      }
    ],
    "preToolUse": [
      {
        "type": "command",
        "bash": "cargo run --manifest-path $WORKSPACE_ROOT/Cargo.toml -p sondera-copilot -- pre-tool-use",
        "cwd": ".",
        "timeoutSec": 60
      }
    ],
    "postToolUse": [
      {
        "type": "command",
        "bash": "cargo run --manifest-path $WORKSPACE_ROOT/Cargo.toml -p sondera-copilot -- post-tool-use",
        "cwd": ".",
        "timeoutSec": 60
      }
    ],
    "errorOccurred": [
      {
        "type": "command",
        "bash": "cargo run --manifest-path $WORKSPACE_ROOT/Cargo.toml -p sondera-copilot -- error-occurred",
        "cwd": ".",
        "timeoutSec": 60
      }
    ]
  }
}
EOF

echo "Installed Sondera Copilot hooks (development mode) to: $HOOKS_DIR/hooks.json"
echo ""
echo "Note: This configuration uses 'cargo run' for development."
echo "For production, use install-hooks-binary.sh instead."
