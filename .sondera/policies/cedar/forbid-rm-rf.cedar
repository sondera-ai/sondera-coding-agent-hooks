@id("forbid-rm-rf")
@description("Block rm invocations that combine recursive and force flags, including bundled flags and common wrappers.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context has parse && context.parse.ok &&
    (
        context.parse.program_flags.contains("rm:-r") ||
        context.parse.program_flags.contains("rm:-R") ||
        context.parse.program_flags.contains("rm:--recursive")
    ) &&
    (
        context.parse.program_flags.contains("rm:-f") ||
        context.parse.program_flags.contains("rm:--force")
    )
    ||
    (
        ( (context has parse && !context.parse.ok) || !(context has parse) ) &&
        (
            context.command like "*rm -rf*" ||
            context.command like "*rm -fr*" ||
            context.command like "*rm -Rf*" ||
            context.command like "*rm -fR*"
        )
    )
};
