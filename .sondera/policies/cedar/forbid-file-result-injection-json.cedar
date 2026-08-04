@id("forbid-file-result-injection-json")
@description("Block JSON file content containing prompt injection — prevents indirect injection via data files.")
forbid (
    principal,
    action == Sondera::Action::"FileOperationResult",
    resource
) when {
    context.path_normalized like "*.json" &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};
