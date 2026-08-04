@id("lol-forbid-service-enumeration")
@description("LotL: block service discovery commands (systemctl list, launchctl list, service --status-all).")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*systemctl list-*" ||
    context.command like "*launchctl list*" ||
    context.command like "*service --status-all*" ||
    context.command like "*chkconfig --list*"
};
