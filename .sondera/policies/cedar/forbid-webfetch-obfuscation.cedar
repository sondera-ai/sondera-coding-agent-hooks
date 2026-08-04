@id("forbid-webfetch-obfuscation")
@description("Block web fetches using obfuscated URLs or prompts to evade detection.")
forbid (
    principal,
    action == Sondera::Action::"WebFetch",
    resource
) when {
    context.signature.categories.contains("obfuscation")
};
