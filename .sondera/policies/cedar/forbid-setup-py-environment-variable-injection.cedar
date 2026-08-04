// Block environment variable injection in setup.py
// Prevents manipulation of build process via environment variables
@id("forbid-setup-py-environment-variable-injection")
@description("Block environment variable injection in setup.py to prevent build process manipulation.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
)
when {
    context.path_normalized like "*/setup.py" &&
    context.signature.categories.contains("command_injection")
};
