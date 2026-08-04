@id("forbid-file-result-injection-csv")
@description("Block CSV/TSV file content containing prompt injection — prevents indirect injection via data imports.")
forbid (
    principal,
    action == Sondera::Action::"FileOperationResult",
    resource
) when {
    (context.path_normalized like "*.csv" || context.path_normalized like "*.tsv") &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};
