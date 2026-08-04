// Block obfuscated package installation commands
// Detects typosquatting and name confusion attacks
// Example: pip install b4se64_encod3r
@id("forbid-suspicious-package-install-obfuscated")
@description("Block obfuscated package installation commands that may indicate typosquatting or name confusion attacks.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
)
when {
    (context.command like "*pip install*" ||
     context.command like "*npm install*" ||
     context.command like "*cargo add*" ||
     context.command like "*gem install*" ||
     context.command like "*apt-get install*") &&
    context.signature.categories.contains("obfuscation") &&
    context.signature.severity >= 2
};
