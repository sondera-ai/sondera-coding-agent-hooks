@id("lol-forbid-read-browser-credentials")
@description("LotL: block reading browser credential stores — prevents password and cookie extraction.")
forbid (
    principal,
    action == Sondera::Action::"FileRead",
    resource
) when {
    context.path_normalized like "*/login data*" ||
    context.path_normalized like "*/cookies*" ||
    context.path_normalized like "*/web data*" ||
    context.path_normalized like "*/logins.json" ||
    context.path_normalized like "*/cookies.sqlite" ||
    context.path_normalized like "*/key4.db" ||
    context.path_normalized like "*/keychain.plist"
};
