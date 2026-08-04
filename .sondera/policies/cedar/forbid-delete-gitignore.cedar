@id("forbid-delete-gitignore")
@description("Block deletion of .gitignore — can cause secrets and build artifacts to be committed.")
forbid (
    principal,
    action == Sondera::Action::"FileDelete",
    resource
) when {
    context.path_normalized like "*.gitignore"
};
