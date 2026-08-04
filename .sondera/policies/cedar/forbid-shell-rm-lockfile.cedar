@id("forbid-shell-rm-lockfile")
@description("Block shell commands that delete lock files — use package manager commands instead.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    (context.command like "*rm *package-lock*" ||
     context.command like "*rm *yarn.lock*" ||
     context.command like "*rm *pnpm-lock*" ||
     context.command like "*rm *Cargo.lock*" ||
     context.command like "*rm *poetry.lock*" ||
     context.command like "*rm *uv.lock*" ||
     context.command like "*rm *go.sum*")
};
