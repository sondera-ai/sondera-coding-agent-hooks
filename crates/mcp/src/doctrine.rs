//! The authoring doctrine, served as a document rather than carried in the
//! prompt.
//!
//! Two reasons it lives here and not inside `autoformalize`. It is stable
//! guidance that does not vary with the intent being formalized, so re-sending
//! it on every invocation is waste; and a prompt that restates what the tools
//! enforce is a second copy of the rules, free to drift from the first. The
//! prompt now points at this document and at the schema resource, and this
//! document points at the tools.

/// The authoring guide, served at `cedar://harness/authoring-guide`.
pub const AUTHORING_GUIDE: &str = r#"# Authoring Cedar for the Sondera harness

How to turn one governance intent into a validated Cedar policy, or into a
refusal that names what the engine cannot express. Refusal is a correct
outcome; a policy that looks right and never fires is not.

## The engine

The baseline permits everything and governance rules are `forbid` statements.
Cedar is deny-overrides, so a single matching `forbid` decides the request. The
only outcome a policy controls is a hard deny — there is no permit-override, no
warn, and no escalate effect. A rule that should merely be visible rather than
blocking is not expressible here; say so rather than approximating it.

Leave `principal` unconstrained unless the intent is genuinely about one actor.
Express the intent through the action scope and the condition.

## Every policy carries

- `@id("kebab-case-id")`, unique within the policy set it joins.
- `@description("one line")`, the rationale an operator reads at adjudication
  time.

Both are required; validation rejects a policy missing either. Uniqueness is
checked across the candidate you submit — when candidates are assembled into
one set later, cross-candidate uniqueness is the assembler's problem. Check an
id is free with `query_baseline_coverage` before assigning it; ids cannot be
discovered by guessing.

Qualify every type with the schema's namespace: `Sondera::Action::"ShellCommand"`,
`Sondera::Label::"Confidential"`. The schema declares `namespace Sondera`, so a
bare `Action::"ShellCommand"` names an undeclared type — against the schema it
fails validation, and without one it silently matches nothing.

## Scope, not condition

Constrain the action in the policy scope:

    forbid (principal, action == Sondera::Action::"ShellCommand", resource)
    when { ... };

Not inside the `when`. The scope is what the engine indexes on and what a
reviewer reads to see which surface a rule covers; an action test buried in a
condition is invisible to both.

Express "block X except Y" as a negated conjunct inside the forbid, never as a
separate `permit`:

    forbid (...) when { <bad> && !(<exception>) };

A `permit` cannot override a `forbid`, so writing the exception as one produces
a policy that blocks the exception too.

## Match what the engine actually produces

Most dead policies are dead because the literal is not a value the engine can
emit. The engine normalizes before matching, and Cedar cannot catch a mismatch
because every one of these is a well-typed `String`.

- `context.path_normalized` is lowercased, with backslashes folded to `/` and
  repeated separators collapsed. A literal with uppercase or a backslash never
  matches. Use `context.path` when the raw spelling is what you mean.
- `context.parse.programs` holds lowercased command *basenames*. `rm` matches
  `/bin/rm`, `sudo rm`, and `RM`; the literal `/bin/rm` matches nothing.
- `context.parse.program_flags` and `program_args` are `program:token` entries
  matched exactly — `"rm:-r"`, not `"-r"`. An unscoped token never matches.
- The `_normalized` companions of those sets lowercase the token and fold
  backslashes; the unnormalized originals preserve case, so `"rm:-R"` is
  correct against `program_flags` and dead against `program_flags_normalized`.
- `context.policy.violations` holds category *codes* — `"SC2"`, not
  `"Injection"`. The human-readable name is prose that travels with the
  template; the code is the closed value the engine emits.

`validate_policy` reports all of these as errors. Get the enumerated values —
signature categories, policy violation codes, label names — from
`get_cedar_policy_context_features` rather than recalling them; they are closed
sets, and an undeclared value is a condition that can never be true.

## Prefer parsed facts to string globs

`like` matching is lexical, and lexical matching over a path or a URL is
evadable: `../`, symlinks, percent-encoding, userinfo (`https://good.com@evil.com`),
case, and alternate spellings all defeat a glob that reads correctly.

- Match hosts with `context.url_parse.host`, gated on `context.url_parse.ok`.
- Match shell structure with `context.parse.*`, gated on `context.parse.ok`.
  The structured view survives flag bundling (`-rf`), flag order, long forms,
  case, absolute paths, and `sudo`/`env`/`xargs` wrappers that a glob does not.

Both parsers can fail. `ok == false` means the structured view is partial or
empty, so a policy that only tests the parsed fields stops firing exactly when
input is malformed enough not to parse — which is the input worth worrying
about. Pair the structured match with a conservative `like` fallback on the raw
field for the `!ok` branch. The shipped baseline has worked examples of this
shape; find them with `query_baseline_coverage`.

When a glob is the only option, say so, and say what it does not cover.

## Labels, signatures, and policy categories are best-effort

The lattice is `Public` < `Internal` < `Confidential` < `HighlyConfidential`.

`== Sondera::Label::"X"` is exact, and it is what the baseline uses. Check the
direction before reaching for `in`: the engine builds each label as a *child* of
the next more sensitive one, so `label in Sondera::Label::"Confidential"` is true
for `Public`, `Internal`, and `Confidential` — that level **or less** sensitive.
It is not "Confidential or above", and `in Sondera::Label::"HighlyConfidential"`
is true of every label, which makes it useless as a gate.

For "at least this sensitive" — the usual shape for an exfiltration or
write-down rule — enumerate the levels explicitly:

    resource.label == Sondera::Label::"Confidential" ||
    resource.label == Sondera::Label::"HighlyConfidential"

`context.label` is the sensitivity of the event being adjudicated right now.
`resource.label` on a `Trajectory` is the accumulated high-water mark across the
run. An outbound gate conditioned on what the agent has already seen wants
`resource.label`; a gate on the content of this specific event wants
`context.label`.

`context.policy` is the third classifier: `violations` holds the category codes a
policy-category model reported for this event's content, and `compliant` is false
when it reported any. Prefer naming the codes you mean —
`context.policy.violations.contains("SC2")` — over `!context.policy.compliant`,
which fires on any template's verdict and so quietly changes meaning whenever a
template is added.

Classification is a model, and it fails open: the label to `Public`, the policy
verdict to compliant with no violations. Both classifiers are also optional, and
off unless the deployment sets `[guardrails] enabled = true` — so a condition
resting on `context.label` or `context.policy` alone covers nothing at all in a
deployment that never turned them on, and stops covering mid-run when the
provider is unreachable or slower than the adjudication budget. Signature
categories are deterministic but they are pattern detection, not proof, and a
reworded instance slips through.

None of the three is a sound basis for a control on its own — pair them with a
structural condition where one exists, and state the residual risk when none
does.

## Pre-action and post-action surfaces

`ShellCommand`, `WebFetch`, and `FileRead`/`Write`/`Edit`/`Delete` adjudicate
*before* the effect: a forbid prevents it.

`ShellCommandOutput`, `WebFetchOutput`, `FileOperationResult`, and `ToolOutput`
adjudicate *after* it. A forbid there stops the content from propagating back to
the agent; it does not undo what already happened. If the intent is that the
action must not run, an output policy alone does not achieve it — pair it with a
pre-action gate, or explain why one is not possible.

## Do not invent context

Use only fields the schema declares — read it at `cedar://harness/schema`. A
field that is not there does not exist, and Cedar will reject it rather than
approximate it, which is the good case; the bad case is reaching for a
different field that typechecks and means something else.

When an intent needs data the engine does not carry, refuse that part. Name the
missing capability specifically, and name the nearest supported alternative if
there is one. Do not approximate an unsupported intent with a string match over
a serialized argument blob or a raw URL.

## Working order

1. Check `query_baseline_coverage` for the surface you are about to write for.
   An existing policy may already cover the intent, or show the shape to follow.
2. Get the exact enumerated values from `get_cedar_policy_context_features`.
3. Read `cedar://harness/schema` for the fields available on that action.
4. Draft, scoped to the narrowest set of actions that covers the intent.
5. Validate with `validate_policy`, passing the schema. Fix errors and re-run.
   Warnings are judgment calls: address them or state why they are acceptable.
6. Present only what validated. A candidate that has not returned `valid: true`
   is not a result, including as an illustration.

The validator is authority over this document. If they disagree, the validator
is right and this guide has a bug worth reporting. Its checks backstop specific
known mistakes — passing them does not certify that a policy expresses your
intent.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// The guide is read inline by an agent, so it has to fit the same client
    /// limits every other served payload does.
    #[test]
    fn the_guide_fits_an_inline_response() {
        assert!(
            AUTHORING_GUIDE.len() <= 12 * 1024,
            "the authoring guide is {} bytes, too large to serve inline",
            AUTHORING_GUIDE.len()
        );
    }

    /// Every tool the guide tells an agent to call has to exist, or following
    /// the guide leads to an error. Only this direction is asserted: a tool
    /// needs no mention in the guide, but a mention needs a tool.
    #[test]
    fn every_tool_the_guide_names_is_exposed() {
        for line in AUTHORING_GUIDE.lines() {
            for word in line.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                if word.starts_with("query_")
                    || word.starts_with("validate_")
                    || word.starts_with("get_cedar_")
                {
                    assert!(
                        crate::TOOL_NAMES.contains(&word),
                        "the guide names `{word}`, which is not an exposed tool"
                    );
                }
            }
        }
    }

    #[test]
    fn every_resource_the_guide_names_is_served() {
        for line in AUTHORING_GUIDE.lines() {
            for word in line.split_whitespace() {
                let uri =
                    word.trim_matches(|c: char| !c.is_ascii_graphic() || c == '`' || c == '.');
                if uri.starts_with("cedar://") {
                    assert!(
                        crate::RESOURCE_URIS.contains(&uri),
                        "the guide names `{uri}`, which is not a served resource"
                    );
                }
            }
        }
    }
}
