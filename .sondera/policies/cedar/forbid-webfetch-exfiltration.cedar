@id("forbid-webfetch-exfiltration")
@description("Block web fetches to exfiltration targets (paste sites, suspicious external domains).")
forbid (
    principal,
    action == Sondera::Action::"WebFetch",
    resource
) when {
    context.signature.categories.contains("exfiltration")
};
