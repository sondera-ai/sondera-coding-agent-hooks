# Getting Started

## Install

Download the archive for Linux x86-64 or Apple silicon from
[GitHub Releases](https://github.com/sondera-ai/sondera-coding-agent-hooks/releases),
then extract it and run from the bundle directory:

```bash
tar -xzf sondera-<target>.tar.gz
cd sondera-<target>
./sondera --help
```

The archive includes the `.sondera/` policy assets required by `sondera serve`,
plus the README, this documentation, and the license. Commands below use
`cargo run` from a source checkout; with an archive, replace
`cargo run -p sondera --` with `./sondera`.

To build from source instead, install [Rust](https://www.rust-lang.org/) and
Cargo using rustup:

```bash
# Install Rust and Cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify installation
cargo --version
```

The YARA signature engine and Cedar policies work without any external
dependencies. The optional LLM-based classifiers are off unless a config file
turns them on, so the harness starts and adjudicates with no provider at all —
see [Configuration](configuration.md) to enable them.

## 1. Start the server

`sondera serve` runs both gRPC surfaces on one address:

| Surface | Where |
|---------|-------|
| `sondera.harness.v1` — adjudication, backed by the Cedar policy engine | `/sondera.harness.v1.HarnessService/…` |
| `sondera.console.v1` — agent and trajectory reads over the same store | `/sondera.console.v1.ConsoleService/…` |

```bash
cargo run -p sondera -- serve -v
```

By default it loads everything from the nearest `.sondera/` directory at or
above the working directory, falling back per asset to `~/.sondera/`, reads and
writes `~/.sondera/trajectories/trajectories.db`, and binds `127.0.0.1:50051`.
[Configuration](configuration.md) covers the flags and environment variables
that override each of those; [Deployment](deployment.md) covers the production
notes.

## 2. Install hooks for Claude Code

`sondera hook claude` registers hooks for all Claude Code lifecycle events
(pre-tool-use, post-tool-use, session-start, etc.). Choose a scope:

```bash
# Local (default) — .claude/settings.local.json, not committed to git
cargo run -p sondera -- hook claude install

# Project — .claude/settings.json, committed to git, shared with team
cargo run -p sondera -- hook claude install --project

# User — ~/.claude/settings.json, applies to all projects
cargo run -p sondera -- hook claude install --user
```

To uninstall, use the same scope flag:

```bash
cargo run -p sondera -- hook claude uninstall --user
```

Hooks for Cursor (`sondera hook cursor`), GitHub Copilot (`sondera hook copilot`),
and Gemini CLI (`sondera hook gemini`) follow the same pattern; `sondera hook
--help` lists every supported provider. Which lifecycle events each provider can
actually block is tabulated in
[crates/hooks/README.md](https://github.com/sondera-ai/sondera-coding-agent-hooks/blob/main/crates/hooks/README.md).

## 3. Watch it work

With the server running and hooks installed, `sondera tui` gives you a
read-only view of every adjudicated run — see [Terminal UI](tui.md).

## Next steps

- [Configuration](configuration.md) — point the harness at a different
  `.sondera/`, or enable the LLM guardrails.
- [Policies](policies.md) — read the shipped corpus and add your own rules.
- [Architecture](architecture.md) — what happens between the hook and the
  verdict.
