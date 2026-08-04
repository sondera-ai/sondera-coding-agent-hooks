@id("forbid-rm-recursive")
@description("Block recursive delete without force flag — still destructive, requires review.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*rm -r /*" ||
    context.command like "*rm -r ~*" ||
    (
        context has parse && context.parse.ok &&
        context.parse.program_flags.containsAny(["rm:-r", "rm:-R", "rm:--recursive"]) &&
        !context.parse.program_flags.containsAny(["rm:-f", "rm:--force"]) &&
        context.parse.program_args.containsAny([
            "rm:/", "rm:~",
            "rm:/etc", "rm:/usr", "rm:/bin", "rm:/sbin", "rm:/lib", "rm:/var",
            "rm:/boot", "rm:/opt", "rm:/home", "rm:/root",
            "rm:/Users", "rm:/System", "rm:/Library",
            "rm:/dev", "rm:/proc", "rm:/sys"
        ])
    )
};
