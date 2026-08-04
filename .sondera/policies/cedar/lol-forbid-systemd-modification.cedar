@id("lol-forbid-systemd-modification")
@description("LotL: block systemd service creation and modification — prevents persistence via system services.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*systemctl enable *" ||
    context.command like "*systemctl daemon-reload*"
};
