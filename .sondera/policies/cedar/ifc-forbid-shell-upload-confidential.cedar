// The Confidential tier of the shell outbound lockdown, and the counterpart to
// `ifc-forbid-webfetch-confidential-with-signatures`. That rule requires
// `context.signature.severity > 2`, and a WebFetch signature scan only covers
// the URL and prompt — so a plain fetch to a clean host never reaches the
// threshold and the Confidential tier has no practical outbound coverage.
//
// Blanket-blocking every network client at Confidential would be too coarse:
// `curl https://api.example.com | jq` is data coming *in*, and reading a public
// endpoint is ordinary work. Cedar cannot see transfer direction, so this keys
// on the flags that make a command upload-shaped, plus the clients that are
// bulk transfer no matter how they are invoked.
@id("ifc-forbid-shell-upload-confidential")
@description("Block outbound shell uploads once the trajectory carries confidential data — curl/wget invoked with a request body, and inherently bulk-transfer clients.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    // Disjoint from `ifc-forbid-shell-egress-highly-confidential`, which covers
    // the tier above unconditionally. Each rule has exactly one job.
    resource.label == Sondera::Label::"Confidential"
    &&
    (
        (
            context has parse && context.parse.ok &&
            (
                // curl carrying a request body or a file upload.
                context.parse.program_flags.contains("curl:-d") ||
                context.parse.program_flags.contains("curl:--data") ||
                context.parse.program_flags.contains("curl:--data-binary") ||
                context.parse.program_flags.contains("curl:--data-raw") ||
                context.parse.program_flags.contains("curl:--data-urlencode") ||
                context.parse.program_flags.contains("curl:--json") ||
                context.parse.program_flags.contains("curl:-F") ||
                context.parse.program_flags.contains("curl:--form") ||
                context.parse.program_flags.contains("curl:-T") ||
                context.parse.program_flags.contains("curl:--upload-file") ||
                // wget's POST-body equivalents.
                context.parse.program_flags.contains("wget:--post-data") ||
                context.parse.program_flags.contains("wget:--post-file") ||
                context.parse.program_flags.contains("wget:--body-data") ||
                context.parse.program_flags.contains("wget:--body-file") ||
                // Clients whose whole purpose is moving bytes to another host;
                // no flag makes these read-only.
                context.parse.programs.contains("scp") ||
                context.parse.programs.contains("sftp") ||
                context.parse.programs.contains("rsync") ||
                context.parse.programs.contains("nc") ||
                context.parse.programs.contains("ncat") ||
                context.parse.programs.contains("netcat") ||
                context.parse.programs.contains("socat") ||
                context.parse.programs.contains("ftp") ||
                context.parse.programs.contains("lftp") ||
                context.parse.programs.contains("tftp")
            )
        )
        ||
        (
            // Parse failure hides the flags this rule depends on, so it falls
            // back to the program-name test the tier above uses. Conservative
            // by intent: unparseable input is the input worth worrying about.
            ( (context has parse && !context.parse.ok) || !(context has parse) ) &&
            (
                context.command like "*curl*" ||
                context.command like "*wget*" ||
                context.command like "*scp *" ||
                context.command like "*sftp*" ||
                context.command like "*rsync*" ||
                // No bare `*nc *`: `like` has no word boundary and it matches
                // inside `myfunc arg`. See the sibling HighlyConfidential rule.
                context.command like "*ncat*" ||
                context.command like "*netcat*" ||
                context.command like "*socat*" ||
                context.command like "*ftp*"
            )
        )
    )
};
