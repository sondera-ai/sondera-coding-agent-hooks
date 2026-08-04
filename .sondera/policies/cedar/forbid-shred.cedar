@id("forbid-shred")
@description("Block shred commands — secure deletion makes recovery impossible.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*shred *"
};
