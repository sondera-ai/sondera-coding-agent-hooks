@id("forbid-docker-rm-force")
@description("Block force removal of running containers — kills processes without graceful shutdown.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*docker rm -f *" ||
    context.command like "*docker rm --force *"
};
