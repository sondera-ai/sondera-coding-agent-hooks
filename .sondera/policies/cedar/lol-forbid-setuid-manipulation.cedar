@id("lol-forbid-setuid-manipulation")
@description("LotL: block setuid/setgid bit manipulation — prevents privilege escalation via SUID binaries.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*chmod *+s *" ||
    context.command like "*chmod *u+s *" ||
    context.command like "*chmod *g+s *" ||
    context.command like "*chmod 4*" ||
    context.command like "*chmod 2*"
};
