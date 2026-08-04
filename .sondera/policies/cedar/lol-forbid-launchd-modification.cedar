@id("lol-forbid-launchd-modification")
@description("LotL: block macOS LaunchAgent/LaunchDaemon creation — prevents persistence via launchd.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*/launchagents/*.plist" ||
    context.path_normalized like "*/launchdaemons/*.plist"
};
