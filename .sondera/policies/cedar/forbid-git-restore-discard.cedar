@id("forbid-git-restore-discard")
@description("Block git restore . — discards all unstaged changes (modern equivalent of checkout .).")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*git restore .*" ||
    context.command like "*git restore --staged --worktree *"
};
