@id("forbid-mkfs")
@description("Block filesystem creation commands — erases all data on the target device.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*mkfs*"
};
