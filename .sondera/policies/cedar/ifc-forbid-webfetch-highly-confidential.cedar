@id("ifc-forbid-webfetch-highly-confidential")
@description("IFC: block all web fetches when trajectory carries highly confidential data — unconditional outbound lockdown.")
forbid (
    principal,
    action == Sondera::Action::"WebFetch",
    resource
) when {
    resource.label == Sondera::Label::"HighlyConfidential"
};
