@id("forbid-file-result-injection-markdown")
@description("Block Markdown file content containing prompt injection — prevents indirect injection via documentation.")
forbid (
    principal,
    action == Sondera::Action::"FileOperationResult",
    resource
) when {
    (context.path_normalized like "*.md" || context.path_normalized like "*.mdx") &&
    (context.signature.categories.contains("prompt_injection") ||
     context.signature.categories.contains("indirect_injection"))
};
