@id("forbid-config-write-secrets-json")
@description("Block writing secrets into JSON config files.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*.json" &&
    context.signature.categories.contains("secrets_detection")
};
