@id("forbid-truncate-table")
@description("Block TRUNCATE TABLE commands — irrecoverably deletes all rows from a table.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*TRUNCATE TABLE*" ||
    context.command like "*TRUNCATE *" ||
    context.command like "*truncate table*"
};
