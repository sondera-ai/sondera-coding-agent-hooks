# Documentation

| Page | What it covers |
|------|----------------|
| [Getting Started](getting-started.md) | Install from a release archive or source, start the harness, wire up your agent |
| [Configuration](configuration.md) | `.sondera/` resolution, `sondera.toml`, and the optional LLM guardrails |
| [Policies](policies.md) | The Cedar corpus, writing custom rules, and the `sondera mcp` authoring server |
| [Terminal UI](tui.md) | Browsing trajectories with `sondera tui` |
| [Architecture](architecture.md) | How a hook event becomes an adjudication, and the normalized event model |
| [Deployment](deployment.md) | Production hardening and the trust boundary around each surface |
| [Development](development.md) | The workspace crates and the checks CI runs |

Commands throughout use `cargo run -p sondera --` from a source checkout. If you
installed from a release archive, replace that with `./sondera`.
