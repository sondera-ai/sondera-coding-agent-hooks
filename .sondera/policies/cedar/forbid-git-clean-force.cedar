@id("forbid-git-clean-force")
@description("Block git clean -f — permanently deletes untracked files.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*git clean -f*" ||
    context.command like "*git clean -df*" ||
    context.command like "*git clean -xf*" ||
    context.command like "*git clean -xdf*"
};
