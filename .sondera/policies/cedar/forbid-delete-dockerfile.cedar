@id("forbid-delete-dockerfile")
@description("Block deletion of Dockerfiles — required for container builds and deployments.")
forbid (
    principal,
    action == Sondera::Action::"FileDelete",
    resource
) when {
    context.path_normalized like "*dockerfile" ||
    context.path_normalized like "*docker-compose*.yml" ||
    context.path_normalized like "*docker-compose*.yaml"
};
