@id("lol-forbid-base64-encode-files")
@description("Block structured base64 file-data staging through base64 and OpenSSL while allowing prose and help/version queries.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context has parse &&
    context.parse.ok &&
    (if context.parse has command_modes then
        context.parse.command_modes.containsAny([
            "base64:encode", "openssl:base64", "openssl:enc-base64"
        ])
    else
    // Legacy contexts lack invocation identity. Retain their historical
    // behavior; modern producers use command_modes and cannot mix flags.
    (
        (
            context.parse.programs.contains("base64") &&
            !context.parse.program_flags.containsAny([
                "base64:-d", "base64:--decode",
                "base64:-h", "base64:--help", "base64:--version"
            ])
        )
        ||
        (
            context.parse.programs.contains("openssl") &&
            (
                (
                    context.parse.program_args.contains("openssl:base64") &&
                    !context.parse.program_flags.containsAny([
                        "openssl:-h", "openssl:--help", "openssl:--version"
                    ])
                )
                ||
                (
                    context.parse.program_args.contains("openssl:enc") &&
                    context.parse.program_flags.containsAny(["openssl:-a", "openssl:-base64"]) &&
                    !context.parse.program_flags.containsAny([
                        "openssl:-h", "openssl:--help", "openssl:--version"
                    ])
                )
            )
        )
    ))
};
