# Gemini CLI Hooks Installation Scripts

This directory contains scripts to install Sondera governance hooks into [Gemini CLI](https://geminicli.com/).

## Quick Start

### Development (using cargo)

```bash
# Local project scope (default, not committed to git)
./install-hooks.sh

# Project scope (committed to git)
./install-hooks.sh --project

# User scope (global, all projects)
./install-hooks.sh --user
```

### Production (using installed binary)

```bash
# First, install the binary
cargo install --path ../

# Then run the installer
./install-hooks-binary.sh              # local scope (default)
./install-hooks-binary.sh --project    # project scope
./install-hooks-binary.sh --user       # user scope
```

### Using the built-in CLI command

```bash
sondera-gemini install              # local scope (default)
sondera-gemini install --project    # project scope
sondera-gemini install --user       # user scope
```

## Installation Scopes

| Scope | Flag | Settings File | Committed to Git |
|-------|------|---------------|------------------|
| Local | `--local` (default) | `.gemini/settings.local.json` | No |
| Project | `--project` | `.gemini/settings.json` | Yes |
| User | `--user` | `~/.gemini/settings.json` | N/A |

The `--project` and `--local` flags accept an optional directory argument:

```bash
./install-hooks.sh --project /path/to/repo
./install-hooks-binary.sh --local /path/to/repo
```

## Prerequisites

1. **Gemini CLI** installed and configured

## What Gets Installed

The scripts create a Gemini CLI settings file with hooks for all lifecycle events:

| Hook Event | Purpose | Impact |
|------------|---------|--------|
| `SessionStart` | Initialize Sondera trajectory when session begins | Inject Context |
| `SessionEnd` | Finalize trajectory when session ends | Advisory |
| `BeforeAgent` | Validate user prompts before agent planning | Block Turn / Context |
| `AfterAgent` | Audit agent responses, enable retry logic | Retry / Halt |
| `BeforeModel` | Validate/modify LLM requests | Block Turn / Mock |
| `AfterModel` | Filter/redact LLM responses | Block Turn / Redact |
| `BeforeToolSelection` | Filter available tools | Filter Tools |
| `BeforeTool` | Validate tool arguments before execution | Block Tool / Rewrite |
| `AfterTool` | Audit tool results, inject context | Block Result / Context |
| `PreCompress` | Log context compression events | Advisory |
| `Notification` | Forward system notifications | Advisory |

## Configuration

### Hook Configuration Format

Each hook follows the [Gemini CLI hooks specification](https://geminicli.com/docs/hooks/):

```json
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "*",
        "hooks": [
          {
            "name": "sondera-before-tool",
            "type": "command",
            "command": "sondera-gemini before-tool",
            "description": "Validate tool execution with Sondera policies",
            "timeout": 30000
          }
        ]
      }
    ]
  }
}
```

### Configuration Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Execution engine (`"command"`) |
| `command` | string | Yes | Shell command to execute |
| `name` | string | No | Friendly name for logs and CLI |
| `timeout` | number | No | Timeout in milliseconds (default: 60000) |
| `description` | string | No | Brief explanation of the hook |
| `matcher` | string | No | Regex (tools) or exact string (lifecycle) |

### Matchers

- **Tool events** (`BeforeTool`, `AfterTool`): Use regex patterns (e.g., `"write_.*"`)
- **Lifecycle events**: Use exact strings (e.g., `"startup"`)
- **Wildcard**: `"*"` or `""` matches all

## Environment Variables

Hooks receive these environment variables from Gemini CLI:

| Variable | Description |
|----------|-------------|
| `GEMINI_PROJECT_DIR` | Absolute path to project root |
| `GEMINI_SESSION_ID` | Unique session identifier |
| `GEMINI_CWD` | Current working directory |

## Managing Hooks

Use Gemini CLI commands to manage hooks without editing JSON:

```bash
# View all hooks
/hooks panel

# Enable/disable all hooks
/hooks enable-all
/hooks disable-all

# Enable/disable specific hook
/hooks enable sondera-before-tool
/hooks disable sondera-before-tool
```

## Troubleshooting

### Hooks not triggering

1. Verify settings file exists: `cat ~/.gemini/settings.json`
2. Restart Gemini CLI
3. Check hook status: `/hooks panel`

### Hook errors

1. Enable verbose logging: Add `--verbose` flag to commands in settings file
2. Check stderr output in Gemini CLI
3. Verify harness server is running

### Connection errors

1. Verify harness endpoint is reachable
2. Check API token is valid
3. Ensure network connectivity

## Uninstalling

```bash
# Using the built-in CLI command
sondera-gemini uninstall              # local scope (default)
sondera-gemini uninstall --project    # project scope
sondera-gemini uninstall --user       # user scope

# Or manually backup and remove settings
mv ~/.gemini/settings.json ~/.gemini/settings.json.backup
```

## Related Documentation

- [Gemini CLI Hooks Documentation](https://geminicli.com/docs/hooks/)
- [Gemini CLI Hooks Reference](https://geminicli.com/docs/hooks/reference)
- [Gemini CLI Best Practices](https://geminicli.com/docs/hooks/best-practices)
