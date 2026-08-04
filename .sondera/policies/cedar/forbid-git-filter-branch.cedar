@id("forbid-git-filter-branch")
@description("Block git filter-branch and filter-repo — rewrites entire repository history.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*git filter-branch*" ||
    context.command like "*git filter-repo*"
};
