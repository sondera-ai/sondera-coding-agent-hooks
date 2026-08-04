@id("forbid-delete-migration-files")
@description("Block deletion of database migration files — can corrupt migration history and break deployments.")
forbid (
    principal,
    action == Sondera::Action::"FileDelete",
    resource
) when {
    context.path_normalized like "*migrations/*.py" ||
    context.path_normalized like "*migrations/*.sql" ||
    context.path_normalized like "*migrations/*.rs" ||
    context.path_normalized like "*migrations/*.ts" ||
    context.path_normalized like "*migrations/*.js"
};
