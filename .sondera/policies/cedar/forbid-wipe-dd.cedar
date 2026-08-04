@id("forbid-wipe-dd")
@description("Block dd commands that write to block devices — can destroy entire disks.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*dd *of=/dev/*"
};
