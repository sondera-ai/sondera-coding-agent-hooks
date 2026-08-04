@id("forbid-dev-null-redirect")
@description("Block redirecting important files to /dev/null — silently destroys data.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*> /dev/null 2>&1 <*" ||
    context.command like "*cat /dev/null >*"
};
