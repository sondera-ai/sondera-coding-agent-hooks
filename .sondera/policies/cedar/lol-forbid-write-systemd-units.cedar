@id("lol-forbid-write-systemd-units")
@description("LotL: block writing systemd unit files — prevents persistence via service definitions.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*/systemd/system/*.service" ||
    context.path_normalized like "*/systemd/user/*.service" ||
    context.path_normalized like "*/etc/init.d/*"
};
