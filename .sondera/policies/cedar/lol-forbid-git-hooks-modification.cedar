@id("lol-forbid-git-hooks-modification")
@description("LotL: block modification of git hook scripts — prevents persistence via repository hooks that execute on git operations.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*/.git/hooks/*"
};
