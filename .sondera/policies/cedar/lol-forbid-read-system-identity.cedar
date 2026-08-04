@id("lol-forbid-read-system-identity")
@description("LotL: block reading system identity files (passwd, group) — agent has no coding use for OS account data.")
forbid (
    principal,
    action == Sondera::Action::"FileRead",
    resource
) when {
    context.path_normalized like "*/etc/passwd" ||
    context.path_normalized like "*/etc/group" ||
    context.path_normalized like "*/etc/shadow" ||
    context.path_normalized like "*/etc/hosts" ||
    context.path_normalized like "*/etc/resolv.conf" ||
    context.path_normalized like "*/etc/hostname"
};
