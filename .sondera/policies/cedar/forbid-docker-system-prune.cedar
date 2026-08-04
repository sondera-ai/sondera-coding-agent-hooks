@id("forbid-docker-system-prune")
@description("Block docker system prune — removes all unused containers, images, networks, and volumes.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*docker system prune*"
};
