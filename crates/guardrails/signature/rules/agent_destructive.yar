/*
 * Agent-Driven Destructive Command Patterns
 *
 * YARA signatures for command shapes that arise when an LLM agent runs a
 * destructive script in a non-interactive shell. These are uncommon in
 * legitimate human use but recurring agent failure modes:
 *
 *   echo n | ./uninstall.sh           — auto-feeds stdin, but the pipe
 *                                       drops the controlling TTY, so any
 *                                       `[ -t 0 ]` interactive guard
 *                                       inside the script silently skips
 *                                       its confirmation prompt and runs
 *                                       the destructive path.
 *
 *   ./uninstall.sh 2>&1 | head -20    — SIGPIPEs the upstream after head
 *                                       reads N lines and exits, killing
 *                                       the script mid-cleanup with side
 *                                       effects half-applied.
 *
 * A real human running an interactive uninstall script types y/n at the
 * prompt; they don't pipe `echo n` in. An agent that pipes input and/or
 * truncates output is almost always trying to "preview" the script
 * without realising both halves of that pipeline defeat the script's
 * safety mechanisms.
 *
 * Destructive keywords are tight on purpose (uninstall|teardown|destroy
 * |purge|wipe|nuke). "remove", "delete", "drop", "clean", and "cleanup"
 * are excluded — they appear in too many benign script names
 * (delete-old-logs.sh, cleanup-tags.sh) and would balloon false
 * positives.
 */

rule agent_auto_confirm_destructive_script {
    meta:
        description     = "echo/printf/yes piped into a destructive script bypasses interactive TTY-gated confirmation"
        action_taxonomy = "interactive_guard_bypass"
        severity        = "high"
        category        = "destructive_action"
        mitre_attack    = "T1485"
        author          = "Sondera Security"
        date            = "2026-04-26"

    strings:
        // echo/printf 'y'|'n'|'yes'|'no' piped into a destructive script —
        // an agent feeding a confirmation token defeats the TTY gate.
        $echo_into_destructive = /\b(echo|printf)\s+["']?(yes|no|y|n)\b[^|]*\|\s*[^|\n]*\b(uninstall|teardown|destroy|purge|wipe|nuke)[^|\n]*\.sh\b/ nocase

        // `yes | ./destroy.sh` — `yes` floods stdin with "y\n" forever, so
        // every prompt the script raises (including ones the agent didn't
        // anticipate) gets auto-confirmed.
        $yes_into_destructive  = /\byes\b\s*\|\s*[^|\n]*\b(uninstall|teardown|destroy|purge|wipe|nuke)[^|\n]*\.sh\b/ nocase

    condition:
        any of them
}

rule agent_truncate_destructive_script {
    meta:
        description     = "Destructive script piped to head/tail SIGPIPEs upstream mid-execution, leaving cleanup half-done"
        action_taxonomy = "sigpipe_truncation"
        severity        = "high"
        category        = "destructive_action"
        mitre_attack    = "T1485"
        author          = "Sondera Security"
        date            = "2026-04-26"

    strings:
        // <destructive>.sh [stdio redirects] | head|tail —
        // when head/tail reads N lines and exits, SIGPIPE kills the
        // upstream script. Partial cleanup state is the worst-of-both
        // outcome: the user thinks the run was a "preview" but real
        // mutations already happened before the pipe broke.
        $destructive_into_head = /\b[^|\n]*\b(uninstall|teardown|destroy|purge|wipe|nuke)[^|\n]*\.sh\b[^|\n]*\|\s*(head|tail)\b/ nocase

    condition:
        any of them
}
