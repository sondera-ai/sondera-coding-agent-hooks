@id("forbid-env-file-write-with-secrets")
@description("Block writing secrets into .env files — detected by YARA secrets_detection rules.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*.env" &&
    context.signature.categories.contains("secrets_detection")
};
