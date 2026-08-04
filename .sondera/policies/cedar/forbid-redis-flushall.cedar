@id("forbid-redis-flushall")
@description("Block Redis FLUSHALL/FLUSHDB — destroys all data in Redis.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*FLUSHALL*" ||
    context.command like "*FLUSHDB*" ||
    context.command like "*flushall*" ||
    context.command like "*flushdb*"
};
