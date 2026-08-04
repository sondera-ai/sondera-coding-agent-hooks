@id("forbid-prompt-injection")
@description("Block prompts containing prompt injection patterns (role manipulation, system override, ignore instructions).")
forbid (
    principal,
    action == Sondera::Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("prompt_injection")
};
