@id("lol-forbid-shell-profile-modification")
@description("LotL: block modification of shell profile and RC files — prevents persistence via shell initialization.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*/.bashrc" ||
    context.path_normalized like "*/.bash_profile" ||
    context.path_normalized like "*/.bash_login" ||
    context.path_normalized like "*/.profile" ||
    context.path_normalized like "*/.zshrc" ||
    context.path_normalized like "*/.zprofile" ||
    context.path_normalized like "*/.zlogin" ||
    context.path_normalized like "*/.zshenv" ||
    context.path_normalized like "*/etc/profile" ||
    context.path_normalized like "*/etc/bash.bashrc" ||
    context.path_normalized like "*/etc/zshrc"
};
