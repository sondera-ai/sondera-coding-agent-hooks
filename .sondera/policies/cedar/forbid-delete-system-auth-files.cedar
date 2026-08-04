@id("forbid-delete-system-auth-files")
@description("Block deletion of system authentication and integrity files through structured file operations.")
forbid (
    principal,
    action == Sondera::Action::"FileDelete",
    resource
) when {
    context.path_normalized like "*/etc/passwd" ||
    context.path_normalized like "*/etc/shadow" ||
    context.path_normalized like "*/etc/gshadow" ||
    context.path_normalized like "*/etc/group" ||
    context.path_normalized like "*/etc/sudoers" ||
    context.path_normalized like "*/etc/sudoers.d/*" ||
    context.path_normalized like "*/etc/pam.d/*" ||
    context.path_normalized like "*/.ssh/authorized_keys" ||
    context.path_normalized like "*/.ssh/authorized_keys2"
};
