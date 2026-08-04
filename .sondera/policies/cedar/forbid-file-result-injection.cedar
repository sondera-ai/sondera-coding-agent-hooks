@id("forbid-file-result-injection")
@description("Block when file content contains prompt injection — prevents indirect injection via file reads.")
forbid (
    principal,
    action == Sondera::Action::"FileOperationResult",
    resource
) when {
    context.signature.categories.contains("prompt_injection") ||
    context.signature.categories.contains("indirect_injection")
};
