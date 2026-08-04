@id("forbid-webfetch-output-critical")
@description("Block web fetch results with critical-severity YARA matches.")
forbid (
    principal,
    action == Sondera::Action::"WebFetchOutput",
    resource
) when {
    context.signature.severity >= 4
};
