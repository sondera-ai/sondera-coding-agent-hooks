@id("lol-forbid-authorized-keys-modification")
@description("LotL: block modification of SSH authorized_keys — prevents persistence via SSH backdoor.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*/.ssh/authorized_keys" ||
    context.path_normalized like "*/.ssh/authorized_keys2"
};
