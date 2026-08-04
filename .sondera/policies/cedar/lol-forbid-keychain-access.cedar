@id("lol-forbid-keychain-access")
@description("LotL: block macOS keychain access via security command — prevents credential extraction from system keychain.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*security find-*" ||
    context.command like "*security dump-keychain*" ||
    context.command like "*security export*" ||
    context.command like "*security show-keychain*"
};
