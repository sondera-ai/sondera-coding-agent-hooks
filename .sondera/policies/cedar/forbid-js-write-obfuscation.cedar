@id("forbid-js-write-obfuscation")
@description("Block writing obfuscated content into JavaScript/TypeScript files.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    (context.path_normalized like "*.js" || context.path_normalized like "*.ts" ||
     context.path_normalized like "*.jsx" || context.path_normalized like "*.tsx") &&
    context.signature.categories.contains("obfuscation")
};
