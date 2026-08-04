@id("forbid-script-write-obfuscation")
@description("Block writing obfuscated content into shell scripts.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    (context.path_normalized like "*.sh" || context.path_normalized like "*.bash" ||
     context.path_normalized like "*.zsh") &&
    context.signature.categories.contains("obfuscation")
};
