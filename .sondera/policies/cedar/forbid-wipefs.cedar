@id("forbid-wipefs")
@description("Block wipefs — erases filesystem signatures from block devices.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*wipefs *"
};
