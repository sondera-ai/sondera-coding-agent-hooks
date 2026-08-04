// Block injection attacks in dependency files
// Prevents command injection and obfuscation in dependency manifests
@id("forbid-dependency-file-injection-attack")
@description("Block injection attacks in dependency manifest files (requirements.txt, package.json, Cargo.toml, etc.).")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
)
when {
    (context.path_normalized like "*/requirements.txt" ||
     context.path_normalized like "*/package.json" ||
     context.path_normalized like "*/cargo.toml" ||
     context.path_normalized like "*/pipfile" ||
     context.path_normalized like "*/setup.py" ||
     context.path_normalized like "*/pyproject.toml" ||
     context.path_normalized like "*/build.rs" ||
     context.path_normalized like "*/webpack.config.js" ||
     context.path_normalized like "*/.gemfile") &&
    (context.signature.categories.contains("command_injection") ||
     context.signature.categories.contains("obfuscation"))
};
