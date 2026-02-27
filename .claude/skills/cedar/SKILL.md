---
name: cedar
description: Authors, validates, and tests Cedar authorization policies and schemas for Sondera AI agent governance. Use when writing .cedar or .cedarschema files, working with agent guardrails, YARA signatures, sensitivity labels, or information flow control policies.
---

# Cedar Policy Authoring for Sondera

Write Cedar policies that govern AI coding agent behavior — shell commands, file operations, web fetches, and prompts —
using YARA signature detection, policy compliance checks, and sensitivity labels.

**Cedar language reference**: See [CEDAR_REFERENCE.md](CEDAR_REFERENCE.md) for full syntax, schema authoring, data
types, operators, templates, authorization patterns, and best practices.

## Workflow

Follow this checklist when authoring Cedar policies:

```
- [ ] Step 1: Discover context features
- [ ] Step 2: Load and analyze schema
- [ ] Step 3: Write policy
- [ ] Step 4: Validate syntax
- [ ] Step 5: Validate against schema
- [ ] Step 6: Format policy
- [ ] Step 7: Test with authorization checks
```

**Step 1: Discover context features**

Call `get_cedar_policy_context_features` to get the latest valid YARA signature categories, policy violation codes, and
sensitivity labels. Always do this before writing policies.

**Step 2: Load and analyze schema**

1. Call `load_schema` with the contents of `policies/base.cedarschema`
2. Call `analyze_schema` to see all actions, principal/resource types, and context fields

To add new entity types or actions, use `create_entity_schema` / `create_action_schema` / `merge_schema_fragments`,
then `validate_schema` on the result.

**Step 3: Write policy**

Use the Sondera context features below and the syntax in [CEDAR_REFERENCE.md](CEDAR_REFERENCE.md).

**Step 4: Validate syntax**

Call `validate_policy` to catch syntax errors.

**Step 5: Validate against schema**

Call `validate_policy_against_schema` with the policy and schema. This catches unknown entity types, type mismatches,
invalid action/principal/resource combinations, and unsafe optional attribute access without `has` guards.

**Step 6: Format**

Call `format_policy` for consistent style before saving.

**Step 7: Test with authorization checks**

1. Call `clear_state` to start clean
2. Call `load_schema` + `load_policies`
3. Call `add_entity` to create test principals, resources, and hierarchy entities
4. Call `is_authorized` with test cases — verify both permit and deny behavior
5. If results don't match expectations: call `analyze_policies`, adjust, re-validate, and re-test

Example `is_authorized` call:

```
principal: Agent::"claude-test"
action: Action::"ShellCommand"
resource: Trajectory::"test-session"
context_json: {
    "workspace": {"cwd": "/tmp", "permission_mode": "default", "transcript_path": ""},
    "signature": {"matches": 1, "categories": ["command_injection"], "severity": 4},
    "policy": {"compliant": false, "violations": ["SC2"]},
    "label": Label::"Confidential",
    "command": "rm -rf /",
    "working_dir": "/tmp"
}
```

---

## Sondera Context Features

**Always call `get_cedar_policy_context_features` first** — the tables below are a static snapshot; the MCP tool returns
the live, authoritative set.

### Actions

| Action                                                | Resource     | Key Context Fields                                                    |
|-------------------------------------------------------|--------------|-----------------------------------------------------------------------|
| `Prompt`                                              | `Message`    | `workspace`, `signature`, `label`                                     |
| `ShellCommand`                                        | `Trajectory` | `workspace`, `signature`, `policy`, `label`, `command`, `working_dir` |
| `ShellCommandOutput`                                  | `Trajectory` | `workspace`, `signature`, `policy`, `label`, `command`, `exit_code`, `stdout`, `stderr` |
| `WebFetch`                                            | `Trajectory` | `workspace`, `signature`, `policy`, `label`, `url`, `prompt`          |
| `WebFetchOutput`                                      | `Trajectory` | `workspace`, `signature`, `policy`, `label`, `url`, `code`, `result`  |
| `FileRead` / `FileWrite` / `FileEdit` / `FileDelete` | `File`       | `workspace`, `signature`, `policy`, `label`, `path`, `operation`      |
| `FileOperationResult`                                 | `Trajectory` | `workspace`, `signature`, `policy`, `label`, `path`, `content`        |
| `ToolOutput`                                          | `Trajectory` | `workspace`, `signature`, `policy`, `label`, `content`                |

### Entity Types

| Entity       | Attributes                                               | Notes                                         |
|--------------|----------------------------------------------------------|-----------------------------------------------|
| `Agent`      | `provider_id: String`                                    | Principal: the AI coding agent                |
| `User`       | —                                                        | Principal: the human user                     |
| `Trajectory` | `step_count: Long`, `label: Label`, `taints: Set<Taint>` | Execution session                             |
| `File`       | `label: Label`                                           | File being operated on                        |
| `Message`    | `content: String`, `role: Role`                          | Message in conversation (child of Trajectory) |
| `Label`      | —                                                        | Sensitivity classification                    |
| `Taint`      | —                                                        | Data provenance taint tag                     |
| `Role`       | —                                                        | Enum: `"user"`, `"model"`, `"system"`, `"tool"` |

### Shared Context Types

```cedar
type WorkspaceContext = {
    cwd: String,
    permission_mode: String,
    transcript_path: String,
};

type SignatureContext = {
    matches: Long,           // number of YARA matches
    categories: Set<String>, // threat categories
    severity: Long,          // 0-4
};

type PolicyContext = {
    compliant: Bool,         // true if no violations
    violations: Set<String>, // e.g. {"SC2", "SC3"}
};
```

### YARA Signature Categories

Available for `context.signature.categories.contains("...")`:

| Category             | Description                                                                           |
|----------------------|---------------------------------------------------------------------------------------|
| `prompt_injection`   | Ignore/disregard instructions, role manipulation, system override                     |
| `indirect_injection` | Indirect injection via document instructions                                          |
| `credential_access`  | Access to sensitive credential/config files, cloud creds, memory dumps                |
| `secrets_detection`  | API keys, cloud creds, private keys, tokens, passwords, DB connection strings         |
| `exfiltration`       | Paste sites, external domains, network commands, DNS tunneling                        |
| `command_injection`  | Shell chaining, path traversal, dangerous commands, reverse shells, cron manipulation |
| `obfuscation`        | Base64, hex, Unicode homoglyphs, HTML entities, URL encoding, concatenation           |
| `defense_evasion`    | Encoding patterns, steganography, HTML/base64 obfuscation                             |
| `tool_abuse`         | Prompt injection to abuse agent tools                                                 |

### Signature Severity Levels

| Level | Meaning  |
|-------|----------|
| 0     | None     |
| 1     | Low      |
| 2     | Medium   |
| 3     | High     |
| 4     | Critical |

### Policy Violation Codes

Available for `context.policy.violations.contains("...")`:

| Code  | Name                     | OWASP/CWE                        |
|-------|--------------------------|-----------------------------------|
| `SC0` | Compliant                | —                                 |
| `SC2` | Injection                | CWE-78/89/79, OWASP A03:2021     |
| `SC3` | Secrets Exposure         | CWE-798/200, OWASP A02:2021      |
| `SC4` | Path Traversal           | CWE-22, OWASP A01:2021           |
| `SC5` | Insecure Deserialization | CWE-502, OWASP A08:2021          |
| `SC6` | Weak Cryptography        | CWE-327/330, OWASP A02:2021      |
| `SC7` | Broken Access Control    | CWE-284/862, OWASP A01:2021      |
| `SC8` | Data Exfiltration        | CWE-200/359/538, OWASP A01:2021  |

### Sensitivity Labels

`context.label` and `resource.label` entity references:

| Label                         | Level | Definition                      |
|-------------------------------|-------|---------------------------------|
| `Label::"Public"`             | 0     | Freely shareable                |
| `Label::"Internal"`           | 1     | Internal use only               |
| `Label::"Confidential"`       | 2     | Sensitive business information  |
| `Label::"HighlyConfidential"` | 3     | PII, credentials, trade secrets |

### Taint Tags

`resource.taints.contains(Taint::"...")` values:

| Taint               | Meaning                                   |
|---------------------|-------------------------------------------|
| `exfiltration`      | Trajectory has shown exfiltration intent  |
| `credential_access` | Trajectory has accessed credential stores |

---

## Policy Examples

```cedar
// Default-permit baseline with targeted forbids
@id("default-permit")
permit (principal, action, resource);

// Block shell commands with injection patterns
@id("forbid-shell-command-injection")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
)
when {
    context.signature.categories.contains("command_injection")
};

// IFC: block writing highly confidential content to public files
@id("forbid-file-write-hc-to-public")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
)
when {
    context.label == Label::"HighlyConfidential" &&
    resource.label == Label::"Public"
};

// Block writing secrets into Python files
@id("forbid-source-write-secrets-python")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
)
when {
    context.path like "*.py" &&
    context.signature.categories.contains("secrets_detection")
};

// Block non-compliant shell commands on sensitive trajectories
@id("forbid-any-destructive-on-confidential-trajectory")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
)
when {
    !context.policy.compliant &&
    (resource.label == Label::"Confidential" ||
     resource.label == Label::"HighlyConfidential")
};

// Block all web fetches on highly confidential trajectories
@id("ifc-forbid-webfetch-highly-confidential")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
)
when {
    resource.label == Label::"HighlyConfidential"
};
```

---

## Key Pitfalls

- **`like` is an infix operator**, not a method: `context.path like "*.py"` (correct) — NOT `context.path.like("*.py")`
- **`*` wildcard matches broadly**: `context.command like "*rm*"` matches `rm` but also `format`, `firmware`
- **Guard optional attributes**: always check `has` before access — `resource has "location" && resource.location == "US"`
- **Explicit deny wins**: a single matching `forbid` overrides all `permit` policies
- **Default deny**: if no policy matches, access is denied
- **Scope over conditions**: use principal/action/resource constraints in policy scope, not in `when` clauses

---

## Quick Reference

```
POLICY:   @id("name") permit|forbid (principal, action, resource) when {...} unless {...};
SCOPE:    == (exact) | in (hierarchy) | is (type check) | in [...] (set)
STRING:   like "pattern*"   (* = wildcard)
SET:      .contains(x)  .containsAll(s)  .containsAny(s)  .isEmpty()
ATTR:     entity.attr  entity["attr"]  entity has "attr"
LOGIC:    &&  ||  !  if...then...else
COMPARE:  ==  !=  <  <=  >  >=
ARITH:    +  -  *  (Long only, no division)
ENTITY:   Type::"id"  Namespace::Type::"id"
```
