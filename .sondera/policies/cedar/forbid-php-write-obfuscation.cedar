@id("forbid-php-write-obfuscation")
@description("Block writing obfuscated content into PHP files.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*.php" &&
    context.signature.categories.contains("obfuscation")
};
