@id("lol-forbid-timestamp-manipulation")
@description("LotL: block timestamp manipulation — timestomping hides malicious file modifications.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*touch -t *" ||
    context.command like "*touch -d *" ||
    context.command like "*touch -r *" ||
    context.command like "*SetFile -d *"
};
