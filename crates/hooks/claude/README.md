# Sondera Claude hooks

Claude Code hooks implemented as a library crate consumed by the umbrella CLI.
The supported invocation is:

```bash
sondera hook claude <subcommand>
```

Install the umbrella CLI, start the harness, then install hooks:

```bash
cargo install --path apps/sondera
sondera serve -v &                 # hooks fail closed without a reachable harness
sondera hook claude install
```

The crate package name is `sondera-claude` for Cargo dependency identity, but it
does not provide a standalone `sondera-claude` binary.

## How it works

Claude Code invokes the CLI once per hook event (for example `PreToolUse`,
`PostToolUse`, `UserPromptSubmit`, `SessionStart`, `Stop`). For each event the
adapter:

1. Reads the hook event JSON from stdin.
2. Normalizes it into `sondera_types` trajectory events (tool calls, file
   operations, shell commands, prompts, lifecycle controls).
3. Connects to the Sondera harness and adjudicates the event via gRPC.
4. Translates the adjudication decision back into the Claude Code hook response
   contract (allow / deny / block / stop, with fail-closed behavior for
   adjudication hooks when the harness is unreachable).

All events are attributed to the Claude Code platform (`provider = "anthropic"`,
`platform = "claude-code"`).

## Subcommands

| Subcommand | Description |
|------------|-------------|
| `install [--user \| --project]` | Register the Sondera hooks in the relevant Claude Code settings scope (local by default). |
| `uninstall [--user \| --project]` | Remove the Sondera hooks from the relevant settings scope. |
| one per hook event | Invoked by Claude Code with the event payload on stdin; not intended to be run by hand. |

Global flag `--verbose` enables debug logging.

`install` wires the 17 events in `event::HOOK_EVENTS`: `config-change`,
`instructions-loaded`, `notification`, `permission-request`, `post-tool-use`,
`post-tool-use-failure`, `pre-compact`, `pre-tool-use`, `session-end`,
`session-start`, `stop`, `subagent-start`, `subagent-stop`, `task-completed`,
`teammate-idle`, `user-prompt-submit`, and `worktree-remove`.

`WorktreeCreate` is deliberately **not** installed. Claude Code treats that hook
as a replacement for its own git worktree creation and requires the command to
print an absolute path on stdout, so registering it would break worktree
creation rather than govern it. `event::hook_spec` still knows the event, for
adapters that opt in.

## Development

```bash
cargo build -p sondera
cargo test -p sondera-claude
cargo clippy --locked -- -D warnings
```
