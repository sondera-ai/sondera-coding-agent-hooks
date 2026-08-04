@id("lol-forbid-suid-discovery")
@description("LotL: block find commands searching for SUID binaries — reconnaissance for privilege escalation.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*find * -perm *4000*" ||
    context.command like "*find * -perm *2000*" ||
    context.command like "*find * -perm */u=s*" ||
    context.command like "*find * -perm */g=s*"
};
