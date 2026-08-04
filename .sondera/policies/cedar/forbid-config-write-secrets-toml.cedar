@id("forbid-config-write-secrets-toml")
@description("Block writing secrets into TOML config files.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*.toml" &&
    context.signature.categories.contains("secrets_detection")
};
