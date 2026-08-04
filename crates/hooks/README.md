# Sondera hook provider crates

The hook adapters are library crates consumed by the umbrella `sondera` binary.
They do not ship standalone provider binaries; users install and run hooks
through the public CLI surface:

```bash
cargo install --path apps/sondera
sondera hook <provider> install
sondera hook <provider> install --user
```

Provider crates live under this namespace:

| Path | Package | Umbrella command |
|------|---------|------------------|
| `crates/hooks/core` | `sondera-hooks` | shared run loop, hook I/O, error classification, and installer scaffolding |
| `crates/hooks/antigravity` | `sondera-antigravity` | `sondera hook antigravity ...` |
| `crates/hooks/claude` | `sondera-claude` | `sondera hook claude ...` |
| `crates/hooks/codex` | `sondera-codex` | `sondera hook codex ...` |
| `crates/hooks/copilot` | `sondera-copilot` | `sondera hook copilot ...` |
| `crates/hooks/cursor` | `sondera-cursor` | `sondera hook cursor ...` |
| `crates/hooks/gemini` | `sondera-gemini` | `sondera hook gemini ...` |
| `crates/hooks/hermes` | `sondera-hermes` | `sondera hook hermes ...` |
| `crates/hooks/opencode` | `sondera-opencode` | `sondera hook opencode ...` |
| `crates/hooks/openhands` | `sondera-openhands` | `sondera hook openhands ...` |
| `crates/hooks/vscode` | `sondera-vscode` | `sondera hook vscode ...` |

Each provider exposes the same library shape used by `apps/sondera`:

- `pub struct Cli` with `#[derive(clap::Args)]`
- `pub async fn run(cli: Cli) -> sondera_hooks::error::Result<()>`

Provider-specific code lives in the provider's own crate:

- `src/install.rs` — the source of truth for that provider's generated hook
  configuration
- `src/response.rs` — the JSON response envelope its host agent parses
- `src/event.rs` — its hook-event matrix, where one exists

`sondera-hooks` holds only what more than one provider needs: the fail-closed
run loop (`runner`), hook I/O (`common`), the shared error type (`error`) and
its classification into user-facing remediation (`diagnostics`), and the
installer scaffolding (`install`). A provider installer supplies its config
path and the splice that adds or removes its hooks; `install::HookConfigInstaller`
does the binary lookup, backup, read/write, and narration around it.

Do not add shell installers or provider `src/main.rs` binaries; new user-facing
commands should be surfaced through `apps/sondera`.

## Tool-name mapping is the enforcement surface

Each adapter maps its host's tool names onto Sondera `Action`s. That mapping is
what decides which Cedar action a call is adjudicated as, so a name the adapter
does not recognize is a name that cannot be governed:

| Adapter maps the call to | Cedar action | Policies that can fire |
|---|---|---|
| `Action::FileOperation` | `FileRead` / `FileWrite` / `FileEdit` / `FileDelete` | the file corpus |
| `Action::ShellCommand` | `ShellCommand` | the shell corpus |
| `Action::WebFetch` | `WebFetch` | the web corpus |
| `Action::ToolCall` (the fallback) | `PreToolUse` | **none** — no policy targets it |

The failure is silent. A `read_file` that lands in the fallback is recorded,
adjudicated, and allowed by `default-permit`; the trajectory shows a clean
`Allow` with no hint that `forbid-private-key-read` was never consulted.

Two rules follow:

- **Match on `sondera_hooks::tool::normalize_tool_name`, not the literal
  string.** Hosts rename tools between versions and are inconsistent about
  casing — VS Code Copilot has shipped both `readFile` and `read_file` for the
  same call. Folding collapses casing and separators so one arm covers every
  spelling.
- **Read paths through `tool::file_path_arg`.** A single host is not internally
  consistent about the argument key either: Gemini CLI's `read_file` takes
  `absolute_path` while its `write_file` takes `file_path`. The wrong key
  yields an empty path, and an empty path satisfies no `path_normalized`
  condition — the policy typechecks and never fires.

Keep the pre- and post-execution mappers in step. A call adjudicated as a
`FileOperation` whose result comes back as a generic `ToolOutput` loses the
content the post-execution signature and sensitivity policies scan, and a
`WebFetch` whose body arrives as a `ToolOutput` is invisible to the
`forbid-webfetch-output-*` corpus.

"In step" has to mean *the same question*, not a similar one. `tool::file_op_for`
and `tool::is_web_tool` classify by name alone, but the builders also require a
path or a URL — so gating the post mapper on the name-only form reports a
`FileOperationResult` for a call the pre mapper adjudicated as a generic
`ToolCall`, and the two halves disagree about what the call was. The post
mappers therefore gate on `tool::is_file_operation` / `tool::is_web_fetch`,
which are *defined as* "the builder would produce one" and so cannot drift from
it; `tool::web_url_arg` resolves the URL the same way on both sides. Adapters
with a fixed tool surface use a shared `FILE_TOOLS` / `WEB_TOOLS` list instead,
with a test asserting every entry maps both ways.

### Shared classifier vs. per-provider arms

Two shapes, chosen by what the host's payload guarantees:

- **Per-provider match arms** (`claude`, `vscode`, `gemini`, `antigravity`,
  `copilot`, `cursor`). The host has a documented, fixed tool surface, and the
  argument keys differ enough per tool to be worth naming — Antigravity's
  PascalCase `TargetFile`, Gemini's split between `absolute_path` and
  `file_path`.
- **`tool::file_operation_for` / `tool::web_fetch_for`** (`codex`, `hermes`,
  `opencode`, `openhands`, and `copilot`'s fallback). These hosts ship a bare
  `tool_name` + `tool_input` envelope and constrain neither, so hand-maintained
  per-adapter lists would drift apart. One classifier covers the union of names
  and handles the multiplexed editors — the Anthropic-style
  `str_replace_editor`, which is one tool whose operation lives in a `command`
  argument of `view` / `create` / `str_replace` / `insert`. Mapping that tool
  wholesale to `FileEdit` would adjudicate a `view` of a credential file as a
  write, and the read policies still would not fire.

  Both classifiers decline a call they cannot ground: a file operation with no
  path (unless it is a patch tool, which names its targets in the diff body),
  and a fetch with no URL. The name sets have to include bare verbs — OpenCode's
  tools really are `read`, `write`, `edit`, and `fetch` — and those collide with
  non-file tools on hosts where any integration can register a name.
  Reclassifying an issue-tracker `create` as a `FileWrite` would run the
  write-side signature policies against its body, which on a fail-closed gate is
  a spurious **deny**, not a mislabelled log line. Requiring a path or a URL
  keeps the collision harmless.

### Current coverage

Every adapter adjudicates every tool call. A name with no specific mapping
becomes a generic `ToolCall` — governed by nothing, but recorded — rather than
being skipped, so the trajectory always shows what the agent did.

| Adapter | Shell | File ops | WebFetch | `@`-mention reads |
|---|---|---|---|---|
| `claude` | ✅ | ✅ read/write/edit (+`Glob`/`Grep` as read) | ✅ | ✅ |
| `vscode` | ✅ | ✅ read/write/edit/delete | ✅ | ✅ `@file:` ‡ |
| `gemini` | ✅ | ✅ read/write/edit | ✅ | ❌ |
| `antigravity` | ✅ | ✅ read/write/edit | ✅ | ❌ |
| `copilot` | ✅ | ✅ read/write/edit | ✅ shared classifier | ❌ |
| `cursor` | ✅ | ✅ read (own hooks) — no `Edit` arm in `preToolUse` | ✅ | ❌ |
| `codex` | ✅ | ✅ shared classifier † | ✅ shared classifier | ❌ |
| `hermes` | ✅ | ✅ shared classifier | ✅ shared classifier | ❌ |
| `opencode` | ✅ | ✅ shared classifier | ✅ | ❌ |
| `openhands` | ✅ | ✅ shared classifier | ✅ shared classifier | ❌ |

† Codex reaches `action_from_tool` from two hooks with different tool
surfaces. `PreToolUse` fires only for `Bash`, but `PermissionRequest` is
installed with a `*` matcher and carries whatever tool needs approval — which
is how a file operation reaches the adapter today. A name missing from the
arms is ungoverned on the approval path, not merely on a hypothetical future
one.

‡ A surface that inlines an `@`-mentioned file into the prompt issues no read
tool call, so nothing reaches `PreToolUse` and no file policy fires. `claude`
and `vscode` re-derive those reads at `UserPromptSubmit` via
`sondera_hooks::mention`, emitting a `Read` `FileOperation` per resolved file
and blocking the prompt when one is denied. The two surfaces spell mentions
differently: Claude Code inlines a path, while VS Code sends the chat-variable
form `@file:<label>` where the label is usually a bare basename, so
`sondera_vscode::mention` strips the scheme and searches the workspace under
`cwd` for it.

Remaining gaps:

- `@`-mention re-derivation is a best-effort re-parse of prompt text, not the
  surface's own resolution. VS Code's other variable prefix (`#file:`) is not
  recognized — `extract_mentions` keys on `@` — and a label containing a space
  is truncated at the space. A static `FileRead` deny remains the authoritative
  block for anything that does reach a tool call.
- The eight adapters marked ❌ above have the same inlining exposure to whatever
  degree their surface supports mentions; none re-derives it yet.

- Only `vscode` and the shared classifier model a `FileDelete`; deletes
  elsewhere arrive as `rm` under the shell corpus.
- `claude` models `Glob`/`Grep` as `FileRead`; `vscode` deliberately leaves
  `list_dir` and the search tools generic. Pick one convention.
- Search tools are never `WebFetch`: they take a query rather than a URL, and
  a `WebFetch` with an empty URL matches no `url_parse` condition. They stay
  generic `ToolCall`s, so no policy governs what an agent searches for.

## Claude degraded-path posture

Two independent timeouts bound a Claude hook:

| Layer | Value | Source |
|---|---|---|
| Sondera hook budget — stdin read, connect, and adjudication together | 30s | `sondera_hooks::runner::DEFAULT_HOOK_BUDGET`, overridable via `SONDERA_HOOK_BUDGET_SECS` up to `MAX_HOOK_BUDGET` (300s) |
| Claude-side hook timeout, written into settings at install | 30s | `sondera_claude::install::HOOK_TIMEOUT_SECS` |

Both layers default to 30 seconds. Lowering `SONDERA_HOOK_BUDGET_SECS` below
the Claude-side timeout gives Sondera time to classify an overrun as
`HookError::BudgetExceeded` and emit its degraded response before Claude ends
the hook process.

Degraded mapping is unconditional — there is no profile or environment switch
that turns it off. `response::fail_closed_response` maps every classified
failure by event:

- Preventive gates fail closed: `PreToolUse` denies, `PermissionRequest` denies
  and interrupts, `PostToolUse` blocks (redacting the tool output when one is
  present), `UserPromptSubmit` blocks the prompt.
- `PreCompact` and `ConfigChange` block, because they gate context rewrite or
  state change. A `ConfigChange` that only touches Sondera's own policy settings
  returns no opinion instead.
- `SubagentStop`, `TaskCompleted`, and `TeammateIdle` block on a normal failure,
  but on `BudgetExceeded` specifically they degrade **open** — an allow carrying
  a `systemMessage`. Blocking these cannot preserve work that already happened,
  so a slow harness should not retroactively fail it.
- Any other event, `Stop` included, returns no response at all, letting Claude
  proceed without model-facing timeout steering.

## Antigravity CLI adapter (`sondera hook antigravity`)

The Antigravity CLI (`agy`) ships its own **Claude-Code-style** hook protocol —
verified against the `agy` binary and the official docs, and distinct from the
Gemini-CLI hooks. `sondera-antigravity` is therefore a standalone adapter (it
does not reuse `sondera-gemini`).

Events and Sondera handling:

| Event | Handling |
|-------|----------|
| `PreToolUse` | **Adjudicated.** Tool call → Sondera `Action` → harness; decision maps to `allow` / `deny` / `ask`. Fail-closed to `deny` if the harness is unreachable. |
| `PostToolUse` | Observation only; records the step result, returns `{}`. |
| `PreInvocation` / `PostInvocation` | Advisory no-op (`{}`); no harness round-trip. |
| `Stop` | Advisory; allows termination (`{"decision":"stop"}`). |

I/O is JSON over stdin/stdout with **camelCase** fields (`conversationId`,
`workspacePaths`, `toolCall`, `stepIdx`, …); the `conversationId` is used as the
trajectory id.

The installer (`crates/hooks/antigravity/src/install.rs`) writes a
*standalone* `hooks.json` whose root maps a **named hook** (`"sondera"`) to its
per-event config:

- **`--user`**: `~/.gemini/config/hooks.json` (global)
- default / **`--workspace`**: `<cwd>/.agents/hooks.json` (takes precedence)

Note the per-event asymmetry from the docs: `PreToolUse`/`PostToolUse` take
`[{matcher, hooks:[…]}]` groups (the matcher targets a tool name like
`run_command`), while `PreInvocation`/`PostInvocation`/`Stop` take a flat array
of handlers directly. `timeout` is in **seconds**.

## Hermes Agent support tier

`sondera hook hermes install` writes Sondera-managed shell-hook entries to
`~/.hermes/config.yaml` and `sondera hook hermes uninstall` removes only those
managed entries. Hermes prompts for shell-hook consent on first use for each
`(event, command)` pair; for non-interactive Gateway sessions, operators must
use Hermes' documented `--accept-hooks`, `HERMES_ACCEPT_HOOKS=1`, or pass
`sondera hook hermes install --auto-accept-all-hooks` to write Hermes-global `hooks_auto_accept: true`.
Shell hooks run with the user's full OS credentials, so the Hermes `hooks:`
block is privileged configuration and should be reviewed like CI or cron.

Support level for the shell-hook adapter:

- Strong enforcement: `pre_tool_call` maps Harness DENY/ESCALATE and backend
  failures to Hermes `{"action":"block","message":...}` responses, so the
  tool handler does not run.
- Strong telemetry: `post_tool_call` records tool observations with the same
  Hermes correlation ID used for the pre-tool action.
- Advisory model steering: `pre_llm_call` can inject steering context, but
  Hermes shell hooks do not hard-block model calls.
- Result/terminal/LLM transform hooks are wired and can emit a forward-compatible
  replacement shape, but current Hermes shell-hook parsing only consumes
  pre-tool block directives and `pre_llm_call` context; replacement support
  requires a Hermes shell-hook extension.
- Approval hooks are observer-only and are not used for Sondera HITL approval.

The Hermes installer sets a 30-second timeout on every hook. Deployments that
route `pre_tool_call` through slower policy backends should size harness latency
accordingly, because blockable hooks fail closed on backend timeouts or
connection errors.

Managed entries embed the absolute path of the `sondera` binary resolved at
install time. If that path goes stale — the binary is moved, or a `cargo
install` lands elsewhere — rerun `sondera hook hermes install` to rewrite it.
