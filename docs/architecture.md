# Architecture

![Architecture](architecture.png)

Each supported agent invokes `sondera hook <provider>` once per lifecycle event
and speaks stdin/stdout JSON to it. The adapter normalizes that payload and
forwards it over **gRPC** to `sondera serve` (loopback TCP, `127.0.0.1:50051` by
default), which coordinates three guardrail subsystems:

1. **Signature Engine** (YARA-X) — pattern-matches tool inputs/outputs for
   prompt injection, data exfiltration, secrets, and obfuscation. Always on, and
   the only one of the three that is deterministic.
2. **Policy Model** — optionally classifies content against the secure-code
   categories in `.sondera/policies.toml`, filling `context.policy.violations`
   with the codes it reports.
3. **Information Flow Control** — optionally assigns sensitivity labels, filling
   `context.label`.

Subsystems 2 and 3 run against whichever LLM provider `.sondera/sondera.toml`
selects, and both are off unless `[guardrails] enabled = true`. Each fails open
when disabled, erroring, or slower than the adjudication budget — to compliant
with no violations, and to `Public` — so Cedar still runs and the deterministic
policies still decide. See [Configuration](configuration.md).

The **Cedar Policy Engine** loads policies and schema fragments — authorable by
a policy agent through the MCP server — combines guardrail signals with entity
state from the **Turso (SQLite) local store**, and returns an adjudication
(Allow / Deny / Escalate) back through the hook adapter to the agent. If the
harness cannot be reached, enforcement hooks **fail closed**.

## Event Model

![Event model](event.png)

The harness models agent execution as a trajectory of typed events. Each hook
adapter normalizes its agent-specific JSON into four event categories:

| Category        | Description                                              | Examples                                                                    |
|-----------------|----------------------------------------------------------|-----------------------------------------------------------------------------|
| **Action**      | Agent-initiated operations, evaluated *before* execution | `ShellCommand`, `FileRead`, `FileWrite`, `FileEdit`, `WebFetch`, `ToolCall` |
| **Observation** | Environment responses, evaluated *after* execution       | `ShellCommandOutput`, `FileOperationResult`, `WebFetchOutput`, `Prompt`     |
| **Control**     | Lifecycle events that manage the trajectory              | `Started`, `Completed`, `Failed`, `Adjudicated`                             |
| **State**       | Snapshots of environment context                         | Working directory, open files, git branch                                   |

Each adapter maps agent-specific tool names to these common types — Claude's
`Bash` tool, Cursor's shell execution hook, Copilot's `bash` tool, and Gemini's
`bash` tool all normalize to the same `ShellCommand` action. The harness
evaluates policies against these normalized events, so one Cedar rule set
governs every supported agent.
[crates/hooks/README.md](https://github.com/sondera-ai/sondera-coding-agent-hooks/blob/main/crates/hooks/README.md)
owns the full mapping.

## References

- [Cedar Policy Language](https://docs.cedarpolicy.com/)
- [Claude Code Hooks](https://code.claude.com/docs/en/hooks)
- [Cursor Agent Hooks](https://cursor.com/docs/agent/hooks)
- [GitHub Copilot Hooks](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/use-hooks)
- [Gemini CLI Hooks](https://geminicli.com/docs/hooks/)
