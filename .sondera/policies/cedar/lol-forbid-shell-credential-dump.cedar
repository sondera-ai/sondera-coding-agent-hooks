@id("lol-forbid-shell-credential-dump")
@description("LotL: block shell commands that dump credentials from OS stores (credential managers, vaults).")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*credential-osxkeychain*" ||
    context.command like "*secret-tool lookup*" ||
    context.command like "*kwallet-query*" ||
    context.command like "*pass show*" ||
    context.command like "*gpg --export-secret*" ||
    context.command like "*gpg -a --export-secret*"
};
