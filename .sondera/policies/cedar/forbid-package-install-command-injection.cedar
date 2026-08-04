// Block package installations with command injection patterns
// Prevents execution of shell commands embedded in install flags
// Example: pip install --before-install "rm -rf /" package
@id("forbid-package-install-command-injection")
@description("Block package installations with command injection patterns embedded in install flags.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
)
when {
    (context.command like "*pip install*" ||
     context.command like "*npm install*" ||
     context.command like "*cargo add*") &&
    context.signature.categories.contains("command_injection") &&
    context.signature.severity >= 3
};
