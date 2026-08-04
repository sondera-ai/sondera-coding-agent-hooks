@id("forbid-git-rebase-no-verify")
@description("Block git operations with --no-verify — bypasses pre-commit hooks and safety checks.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*git commit --no-verify*" ||
    context.command like "*git push --no-verify*" ||
    context.command like "*git merge --no-verify*"
};
