@id("forbid-delete-security-config")
@description("Block deletion of security configuration files — can disable authentication and authorization.")
forbid (
    principal,
    action == Sondera::Action::"FileDelete",
    resource
) when {
    context.path_normalized like "*.eslintrc*" ||
    context.path_normalized like "*security.yml" ||
    context.path_normalized like "*security.yaml" ||
    context.path_normalized like "*codeowners" ||
    context.path_normalized like "*.pre-commit-config.yaml"
};
