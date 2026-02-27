# Claude Code Hooks Installation Scripts

This directory contains installation scripts for the Sondera Claude Code hooks integration.

## Overview

The Sondera Claude Code hooks integrate with Claude Code's lifecycle events to:
- Track session starts and ends
- Capture user prompts
- Monitor tool use (pre and post execution)
- Handle permission requests
- Publish trajectory steps to Sondera Harness

## Installation Scopes

Hooks can be installed at three different scopes:

| Scope | Settings File | Committed to Git | Description |
|-------|--------------|-------------------|-------------|
| **user** | `~/.claude/settings.json` | N/A | Global settings for all projects |
| **project** | `<project>/.claude/settings.json` | Yes | Project-specific, shared with team |
| **local** | `<project>/.claude/settings.local.json` | No | Project-specific, personal only |

## Installation Methods

### Method 1: Development (Cargo Run)

For development, use the cargo-based installer that compiles and runs on demand:

```bash
# User scope (default)
./apps/claude/scripts/install-hooks.sh

# Project scope (committed to git, shared with team)
./apps/claude/scripts/install-hooks.sh --project

# Project scope with explicit directory
./apps/claude/scripts/install-hooks.sh --project /path/to/project

# Local scope (not committed to git)
./apps/claude/scripts/install-hooks.sh --local
```

This installs hooks that run via `cargo run`, which:
- Automatically recompiles when source changes
- Provides detailed error messages
- Is slower but convenient for development

### Method 2: Production (Binary)

For production use, first install the binary, then run the binary installer:

```bash
# Install the binary
cargo install --path apps/claude

# User scope (default)
./apps/claude/scripts/install-hooks-binary.sh

# Project scope (committed to git, shared with team)
./apps/claude/scripts/install-hooks-binary.sh --project

# Project scope with explicit directory
./apps/claude/scripts/install-hooks-binary.sh --project /path/to/project

# Local scope (not committed to git)
./apps/claude/scripts/install-hooks-binary.sh --local
```

This installs hooks using the pre-compiled `sondera-claude` binary, which:
- Starts up instantly
- Has minimal overhead
- Is recommended for daily use

### Method 3: CLI (Recommended)

The `sondera-claude` binary has a built-in install command:

```bash
# Local scope (default)
sondera-claude install

# Project scope
sondera-claude install --project

# User scope
sondera-claude install --user
```

## Configuration

The installer creates a settings file with hooks for all Claude Code lifecycle events:

| Hook | Purpose |
|------|---------|
| **PreToolUse** | Intercept tool invocations before execution |
| **PermissionRequest** | Allow or deny permission requests |
| **PostToolUse** | Process tool results for monitoring |
| **UserPromptSubmit** | Capture user prompts |
| **Notification** | Process system notifications |
| **Stop** | Handle agent stop requests |
| **SubagentStop** | Handle subagent termination |
| **PreCompact** | Process conversation compaction |
| **SessionStart** | Initialize trajectory tracking |
| **SessionEnd** | Finalize trajectory |

## Backup and Restore

The installer automatically backs up existing settings before making changes:
- Backups are named `<original-name>.backup.YYYYMMDD_HHMMSS.json`
- Located alongside the original settings file

To restore:
```bash
cp ~/.claude/settings.json.backup.YYYYMMDD_HHMMSS ~/.claude/settings.json
```

## Troubleshooting

### Binary Not Found

```bash
# Verify installation
which sondera-claude

# If not found, install it
cargo install --path apps/claude

# Or add cargo bin to PATH
export PATH="$HOME/.cargo/bin:$PATH"
```

### Hooks Not Firing

1. Verify settings: `cat ~/.claude/settings.json` (or the project-level file)
2. Test binary: `sondera-claude --help`
3. Check logs for errors
4. Restart Claude Code

### Connection Issues

1. Verify harness is running
2. Review stderr output from hooks

## Uninstalling

To remove the hooks:

```bash
# Using the CLI (recommended)
sondera-claude uninstall              # Local scope
sondera-claude uninstall --project    # Project scope
sondera-claude uninstall --user       # User scope

# Or manually remove the settings file (or restore from backup)
rm ~/.claude/settings.json
rm .claude/settings.json
rm .claude/settings.local.json

# Optional: Uninstall binary
cargo uninstall sondera-claude
```

## Additional Resources

- Claude Code hooks documentation: https://docs.anthropic.com/en/docs/claude-code/hooks
- Sondera architecture: see `docs/` directory
- Hook implementation: `apps/claude/src/app/`
