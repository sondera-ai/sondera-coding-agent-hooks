@id("forbid-file-result-injection-yaml")
@description("Block YAML file content containing prompt injection — prevents indirect injection via config files.")
forbid (
    principal,
    action == Sondera::Action::"FileOperationResult",
    resource
) when {
    (context.path_normalized like "*.yaml" || context.path_normalized like "*.yml") &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};
