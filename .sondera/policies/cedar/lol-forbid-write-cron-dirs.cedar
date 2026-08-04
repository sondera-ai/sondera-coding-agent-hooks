@id("lol-forbid-write-cron-dirs")
@description("LotL: block writing to cron directories — prevents persistence via cron.d, cron.daily, etc.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*/etc/cron*" ||
    context.path_normalized like "*/var/spool/cron/*" ||
    context.path_normalized like "*/var/at/*"
};
