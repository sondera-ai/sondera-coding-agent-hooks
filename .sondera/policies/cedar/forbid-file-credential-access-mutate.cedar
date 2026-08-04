@id("forbid-file-credential-access-mutate")
@description("Block writing, editing, or deleting files detected as credentials or secrets.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit", Sondera::Action::"FileDelete"],
    resource
) when {
    context.signature.categories.contains("credential_access")
};
