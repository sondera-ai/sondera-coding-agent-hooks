@id("forbid-file-write-hc-to-public")
@description("IFC: block writing highly confidential content to a file labeled Public — prevents data spillage.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.label == Sondera::Label::"HighlyConfidential" &&
    resource.label == Sondera::Label::"Public"
};
