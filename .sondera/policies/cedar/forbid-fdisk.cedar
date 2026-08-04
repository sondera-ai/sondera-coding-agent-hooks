@id("forbid-fdisk")
@description("Block fdisk/parted — partition table modification can destroy all data on a disk.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*fdisk *" ||
    context.command like "*parted *" ||
    context.command like "*gdisk *"
};
