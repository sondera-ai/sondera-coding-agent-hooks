// Block secrets in installation and build configuration files
// Prevents exposure of credentials in package metadata
@id("forbid-install-script-with-secrets")
@description("Block secrets in installation and build configuration files to prevent credential exposure.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
)
when {
    (context.path_normalized like "*/install.sh" ||
     context.path_normalized like "*/setup.sh" ||
     context.path_normalized like "*/requirements.txt" ||
     context.path_normalized like "*/package.json") &&
    context.signature.categories.contains("secrets_detection") &&
    context.signature.severity >= 3
};
