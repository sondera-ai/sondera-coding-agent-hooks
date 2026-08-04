@id("forbid-indirect-injection")
@description("Block prompts containing indirect injection via embedded document instructions.")
forbid (
    principal,
    action == Sondera::Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("indirect_injection")
};
