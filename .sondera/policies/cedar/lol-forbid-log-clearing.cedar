@id("lol-forbid-log-clearing")
@description("LotL: block log clearing and truncation commands — prevents evidence destruction.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*truncate -s 0 *log*" ||
    context.command like "*> /var/log/*" ||
    context.command like "*cat /dev/null > *log*" ||
    context.command like "*rm */var/log/*" ||
    context.command like "*journalctl --vacuum*" ||
    context.command like "*log erase *" ||
    context.command like "*history -c*" ||
    context.command like "*history -w*" ||
    context.command like "*unset HISTFILE*" ||
    context.command like "*HISTSIZE=0*" ||
    context.command like "*export HISTFILE=/dev/null*"
};
