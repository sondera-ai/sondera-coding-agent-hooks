@id("forbid-env-file-write-with-credentials")
@description("Block writing credentials into .env files — detected by YARA credential_access rules.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*.env" &&
    context.signature.categories.contains("credential_access")
};
