# Coding Agent Hooks by Sondera

> Released as part of the *Hooking Coding Agents with the Cedar Policy Language*
> talk at [Unprompted 2026](https://unpromptedcon.org/), and updated for
> presentation at
> [Black Hat Arsenal 2026](https://blackhat.com/us-26/arsenal/schedule/index.html)
> and the
> [Vegas AI Security Forum '26](https://aisecurity.forum/events/vegas-ai-security-forum-26/).
> See also our ICML 2026 *Agents in the Wild* workshop paper:
> [arXiv:2606.26649](https://arxiv.org/abs/2606.26649).

A reference monitor for AI coding agents. Rust hook binaries and
[Cedar](https://docs.cedarpolicy.com/) policies intercept every shell command,
file operation, and web request to forbid exfiltration and destructive
behaviors, and enforce information flow control. YARA signatures and Cedar
policy evaluation are deterministic. The optional LLM-based classifiers (data
sensitivity, secure code policy) are probabilistic and configurable in
`.sondera/sondera.toml` — see [Configuration](docs/configuration.md).

Works with [Claude Code](https://code.claude.com/docs/en/hooks),
[Cursor](https://cursor.com/docs/agent/hooks),
[GitHub Copilot](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/use-hooks),
and [Gemini CLI](https://geminicli.com/docs/hooks/), plus adapters for
Antigravity, Codex, Hermes, OpenCode, OpenHands, and VS Code —
`sondera hook --help` lists the full set.

![Architecture](docs/architecture.png)

A hook adapter normalizes its agent's event and forwards it over gRPC to
`sondera serve`, which combines deterministic signature scanning with Cedar
policy evaluation and returns Allow, Deny, or Escalate. If the harness cannot be
reached, enforcement hooks fail closed.

## Enforcement at a glance

What each adapter can do with a decision, by hook group — **block** (deny,
fail-closed), **ask** (escalate to the host's approval UI), **steer** (inject
context), **redact** (replace tool output), **terminate** (stop the loop),
*observe* (recorded only):

| Adapter | PreModel | PostModel | PreTool | PostTool |
|---|---|---|---|---|
| Claude Code | block · steer | *observe* | block · ask | block · redact |
| VS Code | block · steer · terminate | *observe* | block · ask | block · steer |
| Gemini CLI | block · steer | block | block | steer |
| Antigravity | *observe* | *observe* | block · ask | *observe* |
| Copilot | block | *observe* | block | *observe* |
| Cursor | block | *observe* | block · ask | *observe* |
| Codex | block | *observe* | block · ask | block |
| Hermes | steer | *observe* | block | *observe* |
| OpenCode | — | — | block · ask | *observe* |
| OpenHands | block · steer | block | block · steer | *observe* |

Terms, the per-event matrix behind each cell, and the caveats it compresses are
defined in
[crates/hooks/README.md](https://github.com/sondera-ai/sondera-coding-agent-hooks/blob/main/crates/hooks/README.md).

## Quick start

Download the archive for Linux x86-64 or Apple silicon from
[Releases](https://github.com/sondera-ai/sondera-coding-agent-hooks/releases),
or build from source with [Rust](https://www.rust-lang.org/) and Cargo. Then:

```bash
# 1. Start the harness (gRPC on 127.0.0.1:50051)
cargo run -p sondera -- serve -v

# 2. Wire hooks into your agent — here, Claude Code
cargo run -p sondera -- hook claude install

# 3. Watch adjudicated runs
cargo run -p sondera -- tui
```

Installed from an archive, those commands are `./sondera serve`, and so on. No
provider or API key is needed: the signature engine and Cedar policies run with
no external dependencies.

[Getting Started](docs/getting-started.md) covers each step in full.

## Documentation

| Page | What it covers |
|------|----------------|
| [Getting Started](docs/getting-started.md) | Install, start the harness, wire up your agent |
| [Configuration](docs/configuration.md) | `.sondera/` resolution, `sondera.toml`, and the optional LLM guardrails |
| [Policies](docs/policies.md) | The 110-policy Cedar corpus, custom rules, and the `sondera mcp` authoring server |
| [Terminal UI](docs/tui.md) | Browsing trajectories with `sondera tui` |
| [Architecture](docs/architecture.md) | How a hook event becomes an adjudication, and the normalized event model |
| [Deployment](docs/deployment.md) | Production hardening and the trust boundary around each surface |
| [Development](docs/development.md) | The workspace crates and the checks CI runs |

## Contributing

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-features -- -D warnings
cargo test --locked --workspace
```

[Development](docs/development.md) lists the rest of what CI runs;
[AGENTS.md](https://github.com/sondera-ai/sondera-coding-agent-hooks/blob/main/AGENTS.md)
holds the working conventions — the local gate, error
handling, and which surface owns which fact.

## License

MIT licensed. See [LICENSE](LICENSE).
