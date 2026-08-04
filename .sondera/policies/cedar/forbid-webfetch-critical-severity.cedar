@id("forbid-webfetch-critical-severity")
@description("Block web fetches that trigger critical-severity YARA rules.")
forbid (
    principal,
    action == Sondera::Action::"WebFetch",
    resource
) when {
    context.signature.severity >= 4
};
