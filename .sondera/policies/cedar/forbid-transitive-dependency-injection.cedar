// Block injection in dependency file results
// Prevents command execution via transitive dependencies
@id("forbid-transitive-dependency-injection")
@description("Block injection in dependency file results to prevent command execution via transitive dependencies.")
forbid (
    principal,
    action == Sondera::Action::"FileOperationResult",
    resource
)
when {
    (context.path_normalized like "*/setup.py" ||
     context.path_normalized like "*/requirements.txt" ||
     context.path_normalized like "*/package.json" ||
     context.path_normalized like "*/cargo.toml") &&
    context.signature.categories.contains("command_injection") &&
    context.signature.severity >= 3
};
