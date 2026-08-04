@id("forbid-private-key-read")
@description("Block reading private key files — agent should never access raw key material.")
forbid (
    principal,
    action == Sondera::Action::"FileRead",
    resource
) when {
    context.path_normalized like "*.pem" ||
    context.path_normalized like "*.key" ||
    context.path_normalized like "*.p12" ||
    context.path_normalized like "*.pfx" ||
    context.path_normalized like "*.jks"
};
