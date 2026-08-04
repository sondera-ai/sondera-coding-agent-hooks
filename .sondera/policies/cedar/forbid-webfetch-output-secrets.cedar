@id("forbid-webfetch-output-secrets")
@description("Block web fetch results that contain detected secrets.")
forbid (
    principal,
    action == Sondera::Action::"WebFetchOutput",
    resource
) when {
    context.signature.categories.contains("secrets_detection")
};
