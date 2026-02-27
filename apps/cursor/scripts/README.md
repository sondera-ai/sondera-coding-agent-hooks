# Cursor Hooks Installation Scripts

This directory contains installation scripts for the Sondera Cursor hooks integration.

## Overview

The Sondera Cursor hooks integrate with Cursor's lifecycle events to:
- Track session starts and ends
- Capture user prompts
- Monitor tool use (pre and post execution)
- Control shell and MCP execution
- Monitor file access and edits
- Publish trajectory steps to Sondera Harness

## Installation Scopes

Hooks can be installed at two different scopes:

| Scope | Hooks File | Description |
|-------|-----------|-------------|
| **user** | `~/.cursor/hooks.json` | Global settings for all projects |
| **project** | `<project>/.cursor/hooks.json` | Project-specific, committed to git |

## Installation Methods

### Method 1: Development (Cargo Run)

For development, use the cargo-based installer that compiles and runs on demand:

```bash
# Project scope (default)
./apps/cursor/scripts/install-hooks.sh

# User scope
./apps/cursor/scripts/install-hooks.sh --user

# Project scope with explicit directory
./apps/cursor/scripts/install-hooks.sh --project /path/to/project
```

This installs hooks that run via `cargo run`, which:
- Automatically recompiles when source changes
- Provides detailed error messages
- Is slower but convenient for development

### Method 2: Production (Binary)

For production use, first install the binary, then run the binary installer:

```bash
# Install the binary
cargo install --path apps/cursor

# Project scope (default)
./apps/cursor/scripts/install-hooks-binary.sh

# User scope
./apps/cursor/scripts/install-hooks-binary.sh --user

# Project scope with explicit directory
./apps/cursor/scripts/install-hooks-binary.sh --project /path/to/project
```

This installs hooks using the pre-compiled `sondera-cursor` binary, which:
- Starts up instantly
- Has minimal overhead
- Is recommended for daily use

### Method 3: CLI (Recommended)

The `sondera-cursor` binary has a built-in install command:

```bash
# Project scope (default)
sondera-cursor install

# User scope
sondera-cursor install --user
```

## Configuration

The installer creates a hooks file with all Cursor lifecycle events:

| Hook | Purpose |
|------|---------|
| **sessionStart** | Initialize trajectory tracking |
| **sessionEnd** | Finalize trajectory |
| **preToolUse** | Control tool usage before execution |
| **postToolUse** | Process tool results for auditing |
| **postToolUseFailure** | Process failed tool executions |
| **subagentStart** | Control subagent creation |
| **subagentStop** | Handle subagent completion |
| **beforeShellExecution** | Control shell commands before execution |
| **afterShellExecution** | Process shell command results |
| **beforeMCPExecution** | Control MCP tool usage before execution |
| **afterMCPExecution** | Process MCP tool results |
| **beforeReadFile** | Control file access before reading |
| **afterFileEdit** | Process file edits for auditing |
| **beforeSubmitPrompt** | Validate prompts before submission |
| **afterAgentResponse** | Track agent responses |
| **afterAgentThought** | Track agent reasoning process |
| **preCompact** | Observe context window compaction |
| **stop** | Handle agent completion |
| **beforeTabFileRead** | Control Tab file access before reading |
| **afterTabFileEdit** | Process Tab edits for auditing |

## Backup and Restore

The installer automatically backs up existing hooks before making changes:
- Backups are named `hooks.backup.YYYYMMDD_HHMMSS.json`
- Located alongside the original hooks file

To restore:
```bash
cp ~/.cursor/hooks.backup.YYYYMMDD_HHMMSS.json ~/.cursor/hooks.json
```

## Troubleshooting

### Binary Not Found

```bash
# Verify installation
which sondera-cursor

# If not found, install it
cargo install --path apps/cursor

# Or add cargo bin to PATH
export PATH="$HOME/.cargo/bin:$PATH"
```

### Hooks Not Firing

1. Verify hooks file: `cat ~/.cursor/hooks.json` (or the project-level file)
2. Test binary: `sondera-cursor --help`
3. Check logs for errors
4. Restart Cursor

### Connection Issues

1. Verify harness is running
2. Review stderr output from hooks

## Uninstalling

To remove the hooks:

```bash
# Using the CLI (recommended)
sondera-cursor uninstall              # Project scope
sondera-cursor uninstall --user       # User scope

# Or manually remove the hooks file (or restore from backup)
rm ~/.cursor/hooks.json
rm .cursor/hooks.json

# Optional: Uninstall binary
cargo uninstall sondera-cursor
```

## Additional Resources

- Cursor hooks documentation: https://cursor.com/docs/agent/hooks
- Sondera architecture: see `docs/` directory
- Hook implementation: `apps/cursor/src/app/`
