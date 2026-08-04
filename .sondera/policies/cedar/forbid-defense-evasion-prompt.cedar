@id("forbid-defense-evasion-prompt")
@description("Block prompts using obfuscation to evade detection (base64, HTML entities, homoglyphs).")
forbid (
    principal,
    action == Sondera::Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("defense_evasion")
};
