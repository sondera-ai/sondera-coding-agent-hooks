// Block command injection in package lock files
// Prevents tampering with pinned dependency versions
@id("forbid-package-lock-tampering-injection")
@description("Block command injection in package lock files to prevent tampering with pinned dependency versions.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
)
when {
    (context.path_normalized like "*/package-lock.json" ||
     context.path_normalized like "*/yarn.lock" ||
     context.path_normalized like "*/cargo.lock" ||
     context.path_normalized like "*/poetry.lock") &&
    context.signature.categories.contains("command_injection")
};
