@id("forbid-private-key-write")
@description("Block writing private key files — agent should not generate or overwrite key material.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*.pem" ||
    context.path_normalized like "*.key" ||
    context.path_normalized like "*.p12" ||
    context.path_normalized like "*.pfx" ||
    context.path_normalized like "*.jks"
};
