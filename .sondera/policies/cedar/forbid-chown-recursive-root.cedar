@id("forbid-chown-recursive-root")
@description("Block recursive chown to root — can lock out the current user from their own files.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*chown -R root *"
};
