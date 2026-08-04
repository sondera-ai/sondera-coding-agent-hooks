// The WebFetch tier of this lockdown lives in
// `ifc-forbid-webfetch-highly-confidential`. That rule is scoped to
// `Sondera::Action::"WebFetch"`, so denying it leaves the agent one `curl` away
// from the same endpoint: ShellCommand is a separate action surface carrying
// its own outbound capability. This is the shell half of the same intent.
@id("ifc-forbid-shell-egress-highly-confidential")
@description("IFC: block shell network clients once the trajectory carries highly confidential data — the ShellCommand half of the WebFetch outbound lockdown.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    // resource.label on a Trajectory is the run's high-water mark: "the agent
    // has already taken in highly confidential data", not "this command is
    // sensitive". Unconditional at this tier, matching the WebFetch rule —
    // an innocent-looking request can still encode data in a URL or header.
    resource.label == Sondera::Label::"HighlyConfidential"
    &&
    (
        (
            context has parse && context.parse.ok &&
            (
                // `programs` is the lowercased basename of every
                // command-position word, so this survives /usr/bin/curl, CURL,
                // pipelines, `&&` chains, `$( )`, and sudo/env/timeout wrappers.
                context.parse.programs.contains("curl") ||
                context.parse.programs.contains("wget") ||
                context.parse.programs.contains("nc") ||
                context.parse.programs.contains("ncat") ||
                context.parse.programs.contains("netcat") ||
                context.parse.programs.contains("socat") ||
                context.parse.programs.contains("telnet") ||
                context.parse.programs.contains("ftp") ||
                context.parse.programs.contains("lftp") ||
                context.parse.programs.contains("tftp") ||
                context.parse.programs.contains("sftp") ||
                context.parse.programs.contains("scp") ||
                context.parse.programs.contains("ssh") ||
                context.parse.programs.contains("rsync") ||
                context.parse.programs.contains("aria2c") ||
                context.parse.programs.contains("httpie") ||
                context.parse.programs.contains("http") ||
                context.parse.programs.contains("xh")
            )
        )
        ||
        (
            // Fallback for input the shell parser could not handle, which is
            // exactly the input worth worrying about.
            ( (context has parse && !context.parse.ok) || !(context has parse) ) &&
            (
                // No bare `*nc *` pattern: Cedar's `like` has no word
                // boundary, so it matches inside `myfunc arg` and `sync now`.
                // `ncat`/`netcat` are distinctive enough to keep; plain `nc` on
                // unparseable input is left to the parsed branch above.
                context.command like "*curl*" ||
                context.command like "*wget*" ||
                context.command like "*ncat*" ||
                context.command like "*netcat*" ||
                context.command like "*socat*" ||
                context.command like "*telnet*" ||
                context.command like "*ftp*" ||
                context.command like "*scp *" ||
                context.command like "*ssh *" ||
                context.command like "*rsync*"
            )
        )
    )
};
