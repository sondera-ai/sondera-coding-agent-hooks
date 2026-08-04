@id("lol-forbid-su")
@description("LotL: block su commands — agent should not switch to other user accounts.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "su *" ||
    context.command like "su" ||
    context.command like "*| su *" ||
    context.command like "*doas *"
};
