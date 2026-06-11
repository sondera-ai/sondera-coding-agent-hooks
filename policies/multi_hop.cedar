// ═══════════════════════════════════════════════════════
// Sondera – Multi-Hop Temporal Monitor Policies
// ═══════════════════════════════════════════════════════
//
// Enforces stateful, multi-hop security properties that no
// single-event Cedar policy can express: "after an untrusted
// read, deny writes to protected paths until approval."
//
// Model: the harness runs a temporal monitor (an FSM) across
// the whole trajectory. The MONITOR — not Cedar — tracks time:
//
//   1. An untrusted read output (web fetch result, output of an
//      untrusted shell command or tool) ARMS the monitor.
//   2. A user-originated approval (Control::Resumed from an
//      allowlisted resumed_by) CLEARS the armed obligation.
//   3. A write to a protected path while armed VIOLATES it.
//
// Cedar adjudicates the DERIVED BOOLEANS only — no new policy
// language is introduced:
//
//   untrusted_pending — the trajectory's Armed-or-Violated fact,
//     written by the harness on every adjudicated event. Present
//     both on the Trajectory entity (resource for ShellCommand)
//     and as a required context attribute (for file operations,
//     whose File resource is keyed globally by path and cannot
//     reach the Trajectory entity).
//
//   protected_path — true when THIS event writes to a protected
//     path, computed by the monitor's own is_protected_write
//     predicate (glob set + shell write-heuristic) so the FSM
//     and Cedar can never disagree (single source of truth).
//
// Both attributes are REQUIRED in the schema: a request missing
// them fails at construction (fail-closed), never silently
// fail-open on a missing attribute.
//
// This file contains forbids only — it must never weaken the
// base default-permit-with-forbids posture.

// ═══════════════════════════════════════════════════════
// §1  Shell – Protected Write While Untrusted Pending
// ═══════════════════════════════════════════════════════
//
// ShellCommand's resource is the Trajectory, so the monitor's
// fact is read directly off the resource entity.

@id("multi-hop-forbid-shell-protected-write-untrusted-pending")
@description("Multi-hop: after an untrusted read with no approval, forbid shell commands that write to protected paths.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    resource.untrusted_pending &&
    context.protected_path
};

// ═══════════════════════════════════════════════════════
// §2  File Operations – Protected Write While Untrusted Pending
// ═══════════════════════════════════════════════════════
//
// FileWrite/FileEdit's resource is the File (keyed globally by
// path, deliberately not parented to a Trajectory), so the
// monitor's fact arrives as a required context attribute.
// FileEdit is included alongside FileWrite because the monitor's
// is_protected_write predicate trips on Write|Edit identically —
// excluding edits would latch the FSM Violated while allowing
// the edit itself.

@id("multi-hop-forbid-file-protected-write-untrusted-pending")
@description("Multi-hop: after an untrusted read with no approval, forbid file writes/edits to protected paths.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.untrusted_pending &&
    context.protected_path
};
