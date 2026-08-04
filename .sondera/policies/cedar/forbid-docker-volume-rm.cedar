@id("forbid-docker-volume-rm")
@description("Block docker volume removal — destroys persistent data in named volumes.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*docker volume rm *" ||
    context.command like "*docker volume prune*"
};
