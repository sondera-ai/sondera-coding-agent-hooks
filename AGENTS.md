# AGENTS.md

Rust workspace: a reference monitor for AI coding agents. Hook adapters
normalize each agent's events, a gRPC harness adjudicates them against Cedar
policies, and the decision goes back to the agent.

## Commands

The local gate is fmt plus clippy scoped to what you touched. Run these, and
only these, before handing work back:

```bash
cargo fmt --all                                       # no build; sub-second
cargo clippy -p <crate> --all-targets -- -D warnings  # once per crate you changed
```

`cargo check -p <crate>` is the faster signal while iterating; clippy subsumes
it at the end.

Run only when the change calls for it:

```bash
cargo doc --no-deps -p <crate>   # you renamed a public item or edited a [`Type`] link
```

Leave these to CI unless you are explicitly asked to run them. Each is a full
workspace build and is not part of the local loop:

```bash
cargo clippy --all-features -- -D warnings         # the gate CI enforces
cargo doc --no-deps --workspace                    # CI enforces doc links
cargo test --workspace                             # CI runs this
```

A cold `target/` — first build after a branch switch or a `cargo update` —
makes even a scoped clippy take minutes. That is the build, not the gate: do
not respond to it by skipping the gate or by widening the scope to amortize it.

Provider-gated integration tests are `#[ignore]`d and need a live model
provider. Do not enable them to "check your work"; CI does not run them either.

Run the stack locally:

```bash
cargo run -p sondera -- serve -v                   # harness + console gRPC on 127.0.0.1:50051
cargo run -p sondera -- tui                        # read-only view of a running server
cargo run -p sondera -- hook claude install        # wire hooks into .claude/settings.local.json
cargo run -p sondera -- mcp                        # Cedar policy-authoring MCP server on stdio
```

## Where things live

| You're changing | Go to | Read first |
|---|---|---|
| A Cedar policy or the schema | `.sondera/policies/cedar/` | `.agents/skills/autoformalize/SKILL.md` |
| How an event becomes a Cedar context | `crates/policy/cedar/src/transform.rs` | `base.cedarschema`, which documents every field |
| One agent's hook wiring or response shape | `crates/hooks/<provider>/` | `crates/hooks/README.md` |
| Behaviour shared by all providers | `crates/hooks/core/` | same |
| Domain types crossing crate boundaries | `crates/types/` | — |
| Shared LLM provider support | `crates/provider/` | `crates/provider/src/lib.rs` |
| What `.sondera/` means and how it resolves | `crates/settings/` | `crates/settings/src/lib.rs`, which owns the config semantics |
| The gRPC wire format | `crates/schema/proto/` | regenerate via `crates/schema/build.rs` |

Three rules that are easy to get wrong:

- **Policies must namespace-qualify every type**: `Sondera::Action::"ShellCommand"`.
  Bare `Action::"…"` parses fine and then never matches.
- **One policy per file, filename equal to its `@id`.** The corpus holds exactly
  110 policies in 110 files — `forbid-*.cedar`, `lol-*.cedar`,
  `ifc-forbid-*.cedar`, plus `base.cedar`'s default permit — and that 1:1 is an
  invariant, not a coincidence. Add a rule as a new file named for its `@id`; do
  not append a second policy to an existing one, and do not reintroduce
  comment-only category files. A `.cedar` file with no uncommented `@id`
  enforces nothing no matter what its header claims, which is why the 25 such
  banners this layout replaced were deleted rather than filled in.
- **`crates/harness` is depended on twice.** Hooks take it as
  `sondera-harness-client` (`default-features = false, features = ["client"]`)
  so they link the gRPC client without the policy engine. Adding a dependency to
  the default feature set puts it in every hook binary.

## Conventions

- Fail closed. A hook that cannot reach the harness denies preventive events; it
  never proceeds unadjudicated. Anything touching `runner.rs`,
  `fail_closed_response`, or a provider's degraded path is security-relevant —
  say so in the PR.
- No `unwrap()` / `expect()` outside tests. `thiserror` in libraries, `anyhow`
  only in binaries.
- `///` documents what a public item does and how to use it; `//` explains why
  the code is shaped the way it is. Prefix safety and context comments
  (`// SAFETY:`, `// CONTEXT:`).
- One surface owns each fact; the others link to it. `base.cedarschema` owns the
  Cedar context fields, `crates/settings/src/lib.rs` owns `.sondera/`
  resolution and guardrail config, `crates/hooks/README.md` owns the tool-name
  mapping. Restating one of those in a second doc comment or README section is
  how a control ends up documented and disarmed — the copy that drifts is the
  one a reader trusts.
- Every `TODO` carries an issue: `// TODO(#42): …`.
- Doc links are deny-level (`[workspace.lints.rustdoc]`), so a renamed item with
  a stale `[`Type`]` reference fails `cargo doc`. CI runs it workspace-wide; when
  you rename or move a public item, check that one crate before you hand off.

## Known gaps

Do not paper over these in docs; fix or report them.

- **`lol-forbid-base64-encode-files` was drafted and never enabled.** It sat
  commented out in the deleted `lotl.cedar` (recover it with
  `git log --diff-filter=D -p -- .sondera/policies/cedar/lotl.cedar`), so
  base64 / `openssl enc` data staging is currently ungoverned on the shell
  surface. It is the one control the banner deletion removed a draft of: either
  author it properly through `.agents/skills/autoformalize/SKILL.md` — the draft
  never had a behavioural check — or record that the gap is accepted.

When you write a user-facing remediation string, name a command that exists.
`sondera` has exactly four subcommands: `hook`, `serve`, `mcp`, and `tui`.
