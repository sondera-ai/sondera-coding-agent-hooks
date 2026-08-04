@id("forbid-webfetch-output-injection")
@description("Block web fetch results containing prompt injection patterns — prevents indirect injection via web content.")
forbid (
    principal,
    action == Sondera::Action::"WebFetchOutput",
    resource
) when {
    context.signature.categories.contains("prompt_injection") ||
    context.signature.categories.contains("indirect_injection")
};
