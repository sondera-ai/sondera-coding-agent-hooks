// Block exfiltration during package publishing
// Prevents credential/data theft when uploading packages
@id("forbid-package-metadata-exfiltration")
@description("Block exfiltration during package publishing to prevent credential and data theft.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
)
when {
    (context.command like "*python setup.py*" ||
     context.command like "*npm publish*" ||
     context.command like "*cargo publish*") &&
    context.signature.categories.contains("exfiltration")
};
