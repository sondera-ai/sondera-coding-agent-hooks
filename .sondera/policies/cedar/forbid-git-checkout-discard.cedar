@id("forbid-git-checkout-discard")
@description("Block git checkout . — discards all unstaged changes in working tree.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*git checkout -- .*" ||
    context.command like "*git checkout .*"
};
