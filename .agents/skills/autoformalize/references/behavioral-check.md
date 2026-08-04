# Proving a policy fires

Load at step 5 of `../SKILL.md`, or when debugging a policy that validates but
does not fire. `validate_policy` proves a candidate is well-formed; only this
proves it matches the input you meant and leaves the near-miss alone.

## The sequence

1. `clear_state` — the store is global and outlives a run; stale policies from
   an earlier check will match yours.
2. `load_schema` with the contents of `.sondera/policies/cedar/base.cedarschema`
   (or the `cedar://harness/schema` resource).
3. `load_policies` with **`.sondera/policies/cedar/base.cedar`'s default-permit
   concatenated ahead of your candidate.** Without it there is nothing to
   produce an ALLOW, so every result is DENY and the near-miss case cannot be
   distinguished from a hit.
4. `add_entity` for every principal and resource whose attributes a condition
   reads — see below.
5. `is_authorized` twice: once with input the policy must deny, once with a
   near-miss that must stay allowed.

## Reading the result

```jsonc
{
  "decision": "DENY",
  "reasons": [{"id": "forbid-rm-rf", "policy_id": "policy1"}],
  "errors": [],
  "request": {...}
}
```

- **`reasons` must name your policy by `@id`.** `policy_id` is Cedar's
  positional name, assigned in `load_policies` order and meaningless on its own.
- **`errors` must be empty.** An erroring policy contributes nothing to the
  decision, so the rule is untested rather than passing.
- **`warnings`, when present, means the run proved less than it appears to.**
  The tool raises one for each of: no schema loaded, policies that errored, and
  a DENY that no policy caused (Cedar's default-deny, which reads exactly like a
  `forbid` firing). An absent `warnings` field is the clean case.
- **`request` echoes the qualified UIDs actually evaluated.** If the action
  comes back as `Action::"FileWrite"` rather than `Sondera::Action::"FileWrite"`,
  no namespaced policy could have matched.

## Entities with attributes

`add_entity` takes `attributes` as a JSON object string. Supply it for any type
whose schema declares attributes — `Agent` (`provider`), `File` (`label`),
`Trajectory` (`step_count`, `label`), `Message` (`content`, `role`) — or the add
is rejected as non-conforming, naming the attribute at fault.

Attribute values use the same escape form as `context_json`, so entity-valued
attributes are written out in full:

```json
{
  "content": "the secret is out",
  "role": {"__entity": {"type": "Sondera::Role", "id": "user"}}
}
```

A request may name an entity that is not in the store, and that is fine until a
policy reads one of its attributes — at which point the policy errors instead of
matching. Conditions on `resource.label` or `principal.provider` therefore need
the entity added first.

Build the `Label` lattice when a test needs it, each level parented to the next
more sensitive one, matching `crates/policy/cedar/src/lib.rs:146`:

```
add_entity Sondera::Label "HighlyConfidential"
add_entity Sondera::Label "Confidential"       parents: ['Sondera::Label::"HighlyConfidential"']
add_entity Sondera::Label "Internal"           parents: ['Sondera::Label::"Confidential"']
add_entity Sondera::Label "Public"             parents: ['Sondera::Label::"Internal"']
```

Note the direction before writing an `in` test: each label is a *child* of the
next more sensitive one, so `in Sondera::Label::"Confidential"` matches
Confidential **and everything less sensitive**. The served authoring guide is
the authority on what that means for a gate.

## Context JSON

`context_json` is a JSON object string, parsed without the schema, so entity
references use the escape form with a **fully qualified** type name.
`"label": Sondera::Label::"Confidential"` is not JSON and is rejected.

```json
{
  "workspace": {"cwd": "/tmp"},
  "label": {"__entity": {"type": "Sondera::Label", "id": "HighlyConfidential"}},
  "policy": {"compliant": true, "violations": []},
  "path_normalized": "/tmp/notes.md"
}
```

Supply every field the action's context type declares — read the shape from
`cedar://harness/schema` rather than copying an example, since a stale field
list is itself a source of false results. `policy` above is the classifier's
no-finding value; to exercise a policy that gates on a violation, set
`{"compliant": false, "violations": ["SC2"]}` with codes from
`get_cedar_policy_context_features`.
