@id("forbid-delete-lockfile")
@description("Block deletion of package lock files — causes non-reproducible builds.")
forbid (
    principal,
    action == Sondera::Action::"FileDelete",
    resource
) when {
    context.path_normalized like "*package-lock.json" ||
    context.path_normalized like "*yarn.lock" ||
    context.path_normalized like "*pnpm-lock.yaml" ||
    context.path_normalized like "*bun.lockb" ||
    context.path_normalized like "*cargo.lock" ||
    context.path_normalized like "*gemfile.lock" ||
    context.path_normalized like "*poetry.lock" ||
    context.path_normalized like "*uv.lock" ||
    context.path_normalized like "*composer.lock" ||
    context.path_normalized like "*go.sum"
};
