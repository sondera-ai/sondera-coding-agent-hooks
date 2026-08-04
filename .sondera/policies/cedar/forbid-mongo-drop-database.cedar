@id("forbid-mongo-drop-database")
@description("Block MongoDB dropDatabase — permanently destroys a MongoDB database.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*dropDatabase*" ||
    context.command like "*.drop()*"
};
