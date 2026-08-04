@id("forbid-tool-abuse-prompt")
@description("Block prompts attempting to abuse agent tools via injection.")
forbid (
    principal,
    action == Sondera::Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("tool_abuse")
};
