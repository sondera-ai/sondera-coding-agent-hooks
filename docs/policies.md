# Policies

Cedar policies and the schema live in `.sondera/policies/cedar/`. At startup the
harness loads them through a `StaticPolicyStore`, which walks that directory and
every subdirectory and compiles all `.cedar` and `.cedarschema` files it finds.

## The shipped corpus

One policy per file, each file named for its `@id` — 110 policies in 110 files,
so the directory listing *is* the coverage list:

```
policies/cedar/            # Everything Cedar; walked recursively
├── base.cedarschema       # Entity types (Agent, Trajectory, Tool, File, Label) and
│                          #   actions, declared under `namespace Sondera { … }`
├── base.cedar             # Default-permit baseline; every governance rule below is a `forbid`
├── forbid-*.cedar         # 77 targeted rules: destructive operations, secret/private-key
│                          #   writes, prompt and result injection, supply-chain tampering
├── lol-*.cedar            # 28 living-off-the-land rules: credential-store reads, shell-profile
│                          #   and systemd/launchd/cron persistence, log and audit tampering
└── ifc-forbid-*.cedar     # 4 information-flow rules: sensitivity-gated outbound blocking
                           #   across the shell egress and WebFetch surfaces
```

Query coverage with the MCP server's `query_baseline_coverage` rather than
reading the tree; it reports what a given surface already forbids and whether an
`@id` is free.

`base.cedarschema` is the authoritative field surface — it documents every
context field a condition can match on.

## Adding your own rules

Drop `.cedar` files anywhere under `.sondera/policies/cedar/` — nesting is free,
since the store recurses. Qualify every type with the schema namespace
(`Sondera::Action::"ShellCommand"`); a bare `Action::"…"` parses fine and then
never matches. The harness evaluates all policies on every hook event; a single
matching `forbid` overrides any `permit`.

## Author policies with an AI assistant

`sondera mcp` is an MCP server for writing those Cedar policies. It grounds an
assistant in this engine rather than in Cedar generally:

- **Resources** — `cedar://harness/authoring-guide` (how to draft for this
  engine), `cedar://harness/schema` (the authoritative field surface), and the
  baseline's default-permit root.
- **`query_baseline_coverage`** — what the shipped baseline already forbids on a
  given surface, and whether an `@id` is taken. The baseline is 110 policies,
  which is a query, not a document.
- **`get_cedar_policy_context_features`** — the closed sets a condition must
  match exactly (signature categories, policy violation codes, sensitivity
  labels), read from the same definitions the engine matches on.
- **`validate_policy`** — Cedar parse, required `@id`/`@description`,
  duplicate-id detection, schema validation, and semantic lints for conditions
  that typecheck but can never fire. Verify-only: the candidate comes back
  unchanged, with structured findings and a record of which checks ran.
- **`autoformalize`** — a prompt that runs that loop for one natural-language
  rule.

The remaining tools are a Cedar scratchpad — load a schema and policies, manage
entities, run `is_authorized` — for trying a policy out by hand.

MCP clients launch it themselves as a subprocess over stdio — it is a per-client
authoring session, not a shared server, so it is its own command rather than an
endpoint on `sondera serve`. For Claude Code:

```bash
claude mcp add sondera -- cargo run --quiet -p sondera -- mcp
```

Installed as a binary, that command is just `sondera mcp`. The working set —
schema, policies, entities — lives in the process and is gone when the client
disconnects; writing a rule out means saving it under
`.sondera/policies/cedar/`.
