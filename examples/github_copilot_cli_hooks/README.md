# GitHub Copilot CLI Hook Enforcement Example

This example shows the local GitHub Copilot CLI hook enforcement path using
the `sondera` binary:

```text
Copilot CLI -> .github/hooks/sondera.json -> sondera copilot ... -> Sondera
```

The existing loose examples in this repository show policy snippets and event
payloads. This directory is a runnable scenario: a hook config, fixture
payloads, a demo Cedar policy pack, and a smoke script that sends Copilot hook
events through `sondera copilot ...`.

## Prerequisites

```bash
sondera auth login
copilot auth login
jq --version
```

Install the `sondera` CLI from your approved release channel. The example uses
the umbrella `sondera copilot ...` commands; it does not require the older
standalone `sondera-copilot` app binary in this repository.

## Install

From a repository where Copilot CLI should run hooks:

```bash
mkdir -p .github/hooks
cp examples/github_copilot_cli_hooks/.github/hooks/sondera.json .github/hooks/sondera.json
```

Or generate a managed hook config from the CLI:

```bash
sondera copilot install
```

## Fixture Smoke

Run the fixture payloads through the canonical commands:

```bash
sondera copilot session-start < fixtures/sessionStart.json
sondera copilot user-prompt-submitted < fixtures/userPromptSubmitted.json
sondera copilot pre-tool-use < fixtures/preToolUse-allow.json
sondera copilot pre-tool-use < fixtures/preToolUse-deny.json
sondera copilot pre-tool-use < fixtures/preToolUse-rewrite.json
sondera copilot permission-request < fixtures/permissionRequest-rewrite.json
sondera copilot post-tool-use-failure < fixtures/postToolUseFailure.json
sondera copilot agent-stop < fixtures/agentStop.json
sondera copilot session-end < fixtures/sessionEnd.json
```

For a repeatable local run, patch the fixtures to a fresh session/workdir and
execute the same sequence:

```bash
SONDERA_BIN=sondera ./scripts/run_fixture_smoke.sh
```

If your shell environment is stored outside the current process, pass it in:

```bash
SONDERA_ENV_FILE="$HOME/.sondera/env.sondera" ./scripts/run_fixture_smoke.sh
```

By default, this proves local hook execution and harness transport. To require
policy-shaped responses, bind the policy pack below to the Copilot agent in
govern mode and run:

```bash
EXPECT_POLICY_DECISIONS=1 ./scripts/run_fixture_smoke.sh
```

To additionally require a `modifiedArgs` rewrite response for the rewrite
fixture, configure a policy binding that rewrites the risky command and run:

```bash
EXPECT_POLICY_DECISIONS=1 EXPECT_REWRITE=1 ./scripts/run_fixture_smoke.sh
```

## Policy Pack

The `policies/` directory is a demo Cedar policy pack that can be bound through
your configured Sondera policy workflow. The hook transport itself still runs
through the local `sondera copilot ...` commands above.

`policies/investment_cli_hooks.cedar` permits normal hook events and denies
risky shell commands that try to delete files or expose investment identifiers.
The rewrite fixture uses the same risky portfolio-report command shape that a
governed policy binding can replace with bounded, read-only arguments through
Copilot's `modifiedArgs` response.

## Investment Scenario

Use prompts and actions that mirror an investment-advisor agent:

- Allowed: inspect a demo portfolio and run a read-only calculation.
- Denied: expose account identifiers or run a destructive shell command.
- Rewrite: replace a risky free-form portfolio report with a bounded read-only
  command through `modifiedArgs`.
- Permission request: exercise Copilot's separate permission service response
  model, which uses `behavior` and `message` rather than `permissionDecision`.

## Troubleshooting

- If hooks do not run, check for `disableAllHooks` in repository or user
  settings.
- If an allowed `preToolUse` bypasses Copilot's native permission UI, verify
  the response is `{}` and does not include an explicit `permissionDecision`.
- If `permissionRequest` behaves like `preToolUse`, confirm the hook command is
  `sondera copilot permission-request`, not `sondera copilot pre-tool-use`.
- If the smoke exits before reaching a policy decision, verify that `sondera`
  can reach its configured harness with the same environment variables.
