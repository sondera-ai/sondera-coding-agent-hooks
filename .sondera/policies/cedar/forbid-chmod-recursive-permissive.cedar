@id("forbid-chmod-recursive-permissive")
@description("Block recursive chmod to overly permissive modes (777, 666) — breaks file security model.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*chmod -R 777 *" ||
    context.command like "*chmod -R 666 *" ||
    context.command like "*chmod -R a+rwx *"
};
