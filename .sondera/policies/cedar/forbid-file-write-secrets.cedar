@id("forbid-file-write-secrets")
@description("Block file writes or edits that would embed secrets into source code.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.signature.categories.contains("secrets_detection")
};
