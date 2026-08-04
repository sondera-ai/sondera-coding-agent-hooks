@id("lol-forbid-sudoers-modification")
@description("LotL: block modification of sudoers files — prevents granting of elevated privileges.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*/etc/sudoers" ||
    context.path_normalized like "*/etc/sudoers.d/*"
};
