@id("lol-forbid-read-ssh-private-keys")
@description("LotL: block reading SSH private keys and config — prevents lateral movement credential theft.")
forbid (
    principal,
    action == Sondera::Action::"FileRead",
    resource
) when {
    context.path_normalized like "*/.ssh/id_*" ||
    context.path_normalized like "*/.ssh/config" ||
    context.path_normalized like "*/.ssh/known_hosts" ||
    context.path_normalized like "*/.ssh/authorized_keys"
};
