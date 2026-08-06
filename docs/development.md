# Development

## Checks

The same commands CI runs:

```bash
# Format, lint, and documentation
cargo fmt --all -- --check
cargo clippy --locked --all-features -- -D warnings
cargo doc --locked --no-deps --workspace

# Test
cargo test --locked --workspace

# Supply chain
cargo deny check
```

CI also runs `buf lint` and `buf format --diff --exit-code` from
`crates/schema/proto/`.

Integration tests that need a reachable model provider are `#[ignore]`d by
default; run them explicitly with `cargo test -- --ignored` once the provider in
`.sondera/sondera.toml` is up.

## Workspace

| Crate                         | Purpose                                                              |
|-------------------------------|----------------------------------------------------------------------|
| `crates/harness`              | gRPC harness transport, background scan dispatch, and hook-side client |
| `crates/policy/cedar`         | Cedar policy engine and event-to-context transformation              |
| `crates/storage`              | Turso (SQLite) local store: event ledger, agent registry, Cedar entities |
| `crates/guardrails/signature` | YARA-X signature scanning (prompt injection, exfiltration, secrets)  |
| `crates/guardrails/ifc`       | LLM-based data classification (Microsoft Purview sensitivity labels) |
| `crates/guardrails/policy`    | LLM-based policy evaluation (secure code generation categories)      |
| `crates/provider`             | Runtime-selected LLM backbone shared across Sondera applications    |
| `crates/trajectory`           | Off-path LLM trajectory log analysis — enrichment, never enforcement |
| `crates/settings`             | `.sondera/` resolution and guardrail configuration semantics         |
| `crates/types`                | Shared domain types (trajectory, events, errors)                     |
| `crates/schema`               | Protobuf / gRPC schema for `sondera.harness.v1` and `sondera.console.v1` |
| `crates/mcp`                  | MCP server for interactive Cedar policy authoring                    |
| `crates/hooks/core`           | Shared hook runtime: install, dispatch, response shaping             |
| `crates/hooks/<provider>`     | Per-provider hook adapters — see [crates/hooks/README.md](https://github.com/sondera-ai/sondera-coding-agent-hooks/blob/main/crates/hooks/README.md) |
| `crates/console`              | Console gRPC surface over the local agent/trajectory store           |
| `crates/tui`                  | Terminal reading view: the run feed and one run's event transcript   |
| `apps/sondera`                | Unified `sondera` CLI: per-provider hooks, `serve`, `mcp`, and `tui` |

`crates/harness` is depended on twice: in full by the server, and as
`sondera-harness-client` (the same package with `default-features = false,
features = ["client"]`) by every hook adapter, so a hook links only the gRPC
client and not the policy engine.

## Conventions

Working conventions for this repository — the local gate, error handling,
documentation rules, and which surface owns which fact — live in
[AGENTS.md](https://github.com/sondera-ai/sondera-coding-agent-hooks/blob/main/AGENTS.md).
